import streamlit as st
import pandas as pd
import re
import io
import json
import zipfile
import requests
import pyodbc
import hashlib
import hmac
from faker import Faker
from faker.providers import internet, person, address, phone_number, company, date_time, bank, misc
from sqlalchemy import create_engine, inspect, text
from snowflake.connector import connect


# ─── Auth configuration ───────────────────────────────────────────────────────
# Add or remove users here. Passwords are SHA-256 hashed.
# To generate a hash: python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

USER_DB = {
    "admin":   _hash("Ar#9598#Ar"),
    "analyst": _hash("analyst@2024"),
    "viewer":  _hash("view#only1"),
    "p.a.sivakumar": _hash("pas001")
}

ROLE_LABELS = {
    "admin":   "Administrator",
    "analyst": "Data Analyst",
    "viewer":  "Viewer",
    "user":    "User01"
}

def _check_credentials(username: str, password: str) -> bool:
    expected = USER_DB.get(username.strip().lower())
    if not expected:
        return False
    return hmac.compare_digest(expected, _hash(password))

def _render_login():
    """Render the login page. Returns True if authenticated."""
    # Centre-column layout
    _, mid, _ = st.columns([1.5, 2, 1.5])
    with mid:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.image("https://img.icons8.com/fluency/96/shield.png", width=72)
        st.markdown("## 🛡️ Database PII Shield")
        st.markdown("##### Please log in to continue")
        st.markdown("<br>", unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Log In", use_container_width=True, type="primary")

            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password.")
                elif _check_credentials(username, password):
                    st.session_state["authenticated"] = True
                    st.session_state["current_user"]  = username.strip().lower()
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password.")

        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("Contact your administrator to request access.")
    return st.session_state.get("authenticated", False)

# ─── Auth gate ────────────────────────────────────────────────────────────────

if not st.session_state.get("authenticated", False):
    st.set_page_config(page_title="PII Shield — Login", layout="centered")
    _render_login()
    st.stop()

st.set_page_config(page_title="PII Data Masker", layout="wide")
st.title("🛡️ Database PII Shield")
st.markdown("Connect to a data source, auto-detect PII columns with Ollama, review, then mask.")

# ─── Regex patterns ───────────────────────────────────────────────────────────

REGEX_PATTERNS = {
    "EMAIL_ADDRESS": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "PHONE_NUMBER":  r'\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
    "US_SSN":        r'\b\d{3}-\d{2}-\d{4}\b',
    "CREDIT_CARD":   r'\b(?:\d[ -]?){13,16}\b',
    "IP_ADDRESS":    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
}

# ─── Masking ──────────────────────────────────────────────────────────────────

def partial_mask(value: str) -> str:
    s = str(value).strip()
    n = len(s)
    if n == 0:   return s
    if n <= 4:   return "*" * n
    if n <= 10:  return s[0] + "*" * (n - 2) + s[-1]
    return s[:2] + "*" * (n - 4) + s[-2:]

def mask_column(series: pd.Series) -> pd.Series:
    return series.astype(str).apply(partial_mask)

def mask_dataframe(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    masked = df.copy()
    for col in cols:
        if col in masked.columns:
            masked[col] = mask_column(masked[col])
    return masked


# ─── Faker helpers ────────────────────────────────────────────────────────────

_faker = Faker()

# Keyword → Faker method map
FAKER_TYPE_MAP = {
    "name": "name", "first_name": "first_name", "last_name": "last_name",
    "fname": "first_name", "lname": "last_name", "email": "email", "mail": "email",
    "phone": "phone_number", "mobile": "phone_number", "cell": "phone_number",
    "ssn": "ssn", "street": "street_address", "address": "address", "addr": "address",
    "city": "city", "state": "state_abbr", "zip": "zipcode", "postal": "postcode",
    "country": "country", "company": "company", "org": "company",
    "username": "user_name", "user": "user_name", "password": "password",
    "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6", "url": "url",
    "dob": "date_of_birth", "birth": "date_of_birth", "date": "date_this_decade",
    "credit_card": "credit_card_number", "card": "credit_card_number", "cc": "credit_card_number",
    "iban": "iban", "account": "bban", "text": "text", "description": "sentence",
    "note": "sentence", "comment": "sentence", "id": "random_int", "uuid": "uuid4",
    "gender": "random_element", "nationality": "country", "job": "job", "title": "job",
    "age": "random_int", "amount": "pyfloat", "price": "pyfloat", "salary": "random_int",
    "latitude": "latitude", "longitude": "longitude", "lat": "latitude",
    "lon": "longitude", "lng": "longitude", "number": "random_int",
    "flag": "boolean", "active": "boolean", "enabled": "boolean", "bool": "boolean",
    "code": "bothify", "sku": "bothify", "ref": "bothify",
    "color": "color_name", "colour": "color_name",
    "currency": "currency_code", "locale": "locale",
    "time": "time", "timestamp": "date_time_this_decade",
    "year": "year", "month": "month_name", "day": "day_of_week",
    "sentence": "sentence", "paragraph": "paragraph",
    "suffix": "suffix", "prefix": "prefix",
    "county": "state", "region": "state", "district": "state",
    "suite": "secondary_address", "apt": "secondary_address",
    "manager": "name", "owner": "name", "employee": "name",
}

def guess_faker_type(col_name: str) -> str:
    """Guess Faker method from column name using keyword matching."""
    col_lower = col_name.lower().replace("-", "_").replace(" ", "_")
    for keyword, faker_fn in FAKER_TYPE_MAP.items():
        if keyword in col_lower:
            return faker_fn
    return "__passthrough__"  # signals: infer from dtype/samples at generation time

# ─── Column profile: analyse samples to guide generation ─────────────────────

def _profile_column(series: pd.Series) -> dict:
    """Derive min, max, nullrate, unique_ratio, date_fmt, enum_values from a sample series."""
    profile = {"nullable": False, "dtype_str": str(series.dtype)}
    non_null = series.dropna()
    if len(series) > 0:
        profile["nullable"] = series.isna().mean() > 0.0
        profile["null_rate"] = float(series.isna().mean())
    else:
        profile["null_rate"] = 0.0

    if len(non_null) == 0:
        return profile

    dtype_str = str(series.dtype)

    # Numeric
    if "int" in dtype_str or "float" in dtype_str:
        profile["min_val"] = float(non_null.min())
        profile["max_val"] = float(non_null.max())
        profile["mean_val"] = float(non_null.mean())
        return profile

    # Boolean
    if "bool" in dtype_str:
        profile["is_bool"] = True
        return profile

    # Datetime
    if "datetime" in dtype_str:
        profile["is_datetime"] = True
        profile["min_val"] = str(non_null.min())
        profile["max_val"] = str(non_null.max())
        return profile

    # String analysis
    str_vals = non_null.astype(str)
    unique_ratio = non_null.nunique() / len(non_null)
    profile["unique_ratio"] = unique_ratio

    # Enum detection: ≤15 unique values covering ≥80% of non-null
    if non_null.nunique() <= 15 and unique_ratio <= 0.5:
        profile["enum_values"] = non_null.value_counts().head(15).index.tolist()

    # Date string detection
    sample_val = str_vals.iloc[0]
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d",
                "%d-%m-%Y", "%m-%d-%Y", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y"):
        try:
            pd.to_datetime(sample_val, format=fmt)
            profile["date_fmt"] = fmt
            profile["is_date_str"] = True
            break
        except Exception:
            pass

    # Numeric-string detection
    try:
        numeric_vals = pd.to_numeric(str_vals, errors="coerce")
        if numeric_vals.notna().mean() > 0.8:
            profile["min_val"] = float(numeric_vals.min())
            profile["max_val"] = float(numeric_vals.max())
            profile["is_numeric_str"] = True
    except Exception:
        pass

    # String length profile
    lengths = str_vals.str.len()
    profile["min_len"] = int(lengths.min())
    profile["max_len"] = int(lengths.max())

    return profile

# ─── Smart value generator ────────────────────────────────────────────────────

def _generate_typed_value(faker_fn: str, profile: dict):
    """Generate a single value respecting the column profile."""

    # Nullable: randomly inject None
    if profile.get("nullable") and profile.get("null_rate", 0) > 0:
        import random
        if random.random() < profile["null_rate"]:
            return None

    dtype_str = profile.get("dtype_str", "")

    # Boolean
    if profile.get("is_bool") or "bool" in dtype_str:
        return _faker.boolean()

    # Enum / categorical
    if "enum_values" in profile:
        return _faker.random_element(elements=profile["enum_values"])

    # Datetime column
    if profile.get("is_datetime"):
        try:
            min_dt = pd.to_datetime(profile.get("min_val"))
            max_dt = pd.to_datetime(profile.get("max_val"))
            return _faker.date_time_between(start_date=min_dt, end_date=max_dt)
        except Exception:
            return _faker.date_time_this_decade()

    # Date string column
    if profile.get("is_date_str"):
        fmt = profile.get("date_fmt", "%Y-%m-%d")
        try:
            return _faker.date_this_decade(before_today=True, after_today=False).strftime(fmt)
        except Exception:
            return _faker.date()

    # Numeric dtype — range-aware
    if "int" in dtype_str or "float" in dtype_str:
        mn = int(profile.get("min_val", 0))
        mx = int(profile.get("max_val", 99999))
        if "float" in dtype_str:
            mn_f = float(profile.get("min_val", 0.0))
            mx_f = float(profile.get("max_val", 99999.0))
            return round(_faker.pyfloat(min_value=mn_f, max_value=mx_f), 2)
        return _faker.random_int(min=mn, max=max(mn, mx))

    # Numeric stored as string
    if profile.get("is_numeric_str"):
        mn = int(profile.get("min_val", 0))
        mx = int(profile.get("max_val", 99999))
        return str(_faker.random_int(min=mn, max=max(mn, mx)))

    # Passthrough: infer from dtype/profile only (no semantic mapping found)
    if faker_fn == "__passthrough__":
        if "int" in dtype_str:
            mn = int(profile.get("min_val", 0))
            mx = int(profile.get("max_val", 99999))
            return _faker.random_int(min=mn, max=max(mn, mx))
        if "float" in dtype_str:
            mn_f = float(profile.get("min_val", 0.0))
            mx_f = float(profile.get("max_val", 99999.0))
            return round(_faker.pyfloat(min_value=mn_f, max_value=mx_f), 2)
        # Unknown string: match original length range
        min_l = profile.get("min_len", 3)
        max_l = profile.get("max_len", 20)
        return _faker.lexify("?" * min(max_l, 20))

    # Named Faker method with smart args
    try:
        fn = getattr(_faker, faker_fn)
        if faker_fn == "random_element":
            return fn(elements=["Male", "Female", "Non-binary"])
        if faker_fn == "random_int":
            mn = int(profile.get("min_val", 0))
            mx = int(profile.get("max_val", 99999))
            return fn(min=mn, max=max(mn + 1, mx))
        if faker_fn == "pyfloat":
            mn_f = float(profile.get("min_val", 0.0))
            mx_f = float(profile.get("max_val", 99999.0))
            return round(fn(min_value=mn_f, max_value=mx_f), 2)
        if faker_fn in ("date_of_birth",):
            return fn(minimum_age=18, maximum_age=90).strftime("%Y-%m-%d")
        if faker_fn == "date_this_decade":
            return fn().strftime("%Y-%m-%d")
        if faker_fn == "date":
            fmt = profile.get("date_fmt", "%Y-%m-%d")
            return fn(pattern=fmt)
        if faker_fn == "date_time_this_decade":
            return str(fn())
        if faker_fn == "bothify":
            return fn(text="??###")
        if faker_fn == "boolean":
            return fn()
        if faker_fn == "zipcode":
            return fn()
        return fn()
    except Exception:
        return _faker.word()

def build_faker_prompt(col_samples: dict) -> str:
    """Build AI prompt with column names AND sample values for better mapping."""
    samples_str = json.dumps(col_samples, indent=2, default=str)
    return f"""You are a data generation assistant. Given column names and sample values from a database table, assign the most appropriate Faker library method for each column.

Available Faker methods: name, first_name, last_name, email, phone_number, ssn, address, street_address, city, state_abbr, zipcode, country, company, user_name, password, ipv4, ipv6, url, date_of_birth, date_this_decade, date_time_this_decade, credit_card_number, iban, bban, text, sentence, uuid4, job, latitude, longitude, random_int, pyfloat, boolean, color_name, currency_code, year, time, suffix, prefix, secondary_address, bothify, word.

Rules:
- Return ONLY a JSON object: keys = column names, values = Faker method names from the list above.
- No markdown fences, no explanation.
- Use sample values to understand the data shape (e.g. 2-letter state codes → state_abbr, Y/N → random_element).
- For numeric ID/PK columns use random_int.
- For columns with only a few distinct values (like status flags), use random_element.
- If truly unsure, use word.

Column samples (name: [sample values]):
{samples_str}

Response (JSON only):"""

def ai_map_faker_columns(columns: list[str], ai_engine: str,
                          df_sample: pd.DataFrame = None,
                          ollama_url=None, ollama_model=None, ollama_timeout=180,
                          sf_conn=None, cortex_model=None) -> dict[str, str]:
    """Map column names to Faker methods using AI + sample values. Falls back to keyword matching."""
    # Build sample dict for the prompt
    col_samples = {}
    if df_sample is not None and not df_sample.empty:
        for col in columns:
            col_samples[col] = df_sample[col].dropna().astype(str).head(5).tolist()
    else:
        col_samples = {col: [] for col in columns}

    prompt = build_faker_prompt(col_samples)
    raw = ""
    try:
        if ai_engine == "Ollama (LLaMA)" and ollama_url and ollama_model:
            resp = requests.post(
                f"{ollama_url.rstrip('/')}/api/chat",
                json={
                    "model": ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"temperature": 0, "num_predict": 1024},
                },
                timeout=ollama_timeout,
            )
            resp.raise_for_status()
            raw = resp.json()["message"]["content"].strip()
        elif ai_engine == "Snowflake Cortex" and sf_conn and cortex_model:
            cur = sf_conn.cursor()
            escaped = prompt.replace("'", "\'")
            cur.execute(f"SELECT SNOWFLAKE.CORTEX.COMPLETE('{cortex_model}', '{escaped}')")
            row = cur.fetchone()
            raw = (row[0] if row else "").strip()

        raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
        result = json.loads(raw)
        if isinstance(result, dict):
            mapped = {}
            for col in columns:
                fn = result.get(col, guess_faker_type(col))
                if fn != "__passthrough__" and not hasattr(_faker, fn):
                    fn = guess_faker_type(col)
                mapped[col] = fn
            return mapped
    except Exception:
        pass
    return {col: guess_faker_type(col) for col in columns}

def generate_fake_dataframe(columns: list[str], faker_map: dict[str, str],
                              df_original: pd.DataFrame, n_rows: int) -> pd.DataFrame:
    """Generate n_rows of realistic fake data respecting original dtypes and value ranges."""
    # Build per-column profiles from original data
    profiles = {}
    for col in columns:
        if df_original is not None and col in df_original.columns and not df_original[col].dropna().empty:
            profiles[col] = _profile_column(df_original[col])
        else:
            profiles[col] = {"dtype_str": "object", "nullable": False, "null_rate": 0.0}

    data = {}
    for col in columns:
        fn      = faker_map.get(col, "__passthrough__")
        profile = profiles[col]
        values  = [_generate_typed_value(fn, profile) for _ in range(n_rows)]

        # Cast to original dtype where possible
        dtype_str = profile.get("dtype_str", "")
        try:
            if "int" in dtype_str and not profile.get("nullable"):
                values = pd.array(values, dtype=dtype_str)
            elif "float" in dtype_str:
                values = pd.array(values, dtype=dtype_str)
            elif "bool" in dtype_str:
                values = [bool(v) if v is not None else None for v in values]
            elif "datetime" in dtype_str:
                values = pd.to_datetime(values, errors="coerce")
        except Exception:
            pass
        data[col] = values

    return pd.DataFrame(data)

# ─── Ollama ───────────────────────────────────────────────────────────────────

def build_prompt(sample_json: str) -> str:
    return f"""You are a PII detection engine. Below is a JSON object where each key is a column name and the value is a list of sample values from that column.

Identify which columns contain Personally Identifiable Information (PII) such as: names, emails, phone numbers, addresses, SSNs, credit card numbers, dates of birth, IP addresses, usernames, or any other sensitive personal data.

Rules:
- Return ONLY a JSON array of column names that contain PII.
- If no PII columns exist, return [].
- Be conservative: only flag columns with clear PII.
- Do NOT include explanations or markdown fences.

Column samples:
{sample_json}

Response (JSON array only):"""

def _call_ollama_batch(columns_sample: dict, base_url: str, model: str, timeout: int, retries: int = 2) -> list[str]:
    prompt = build_prompt(json.dumps(columns_sample, indent=2))
    last_err = None
    for attempt in range(1, retries + 2):
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"temperature": 0, "num_predict": 256},
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            raw = resp.json()["message"]["content"].strip()
            raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
            result = json.loads(raw)
            if isinstance(result, list):
                return [c for c in result if c in columns_sample]
            return []
        except requests.exceptions.Timeout as e:
            last_err = e
            if attempt <= retries:
                st.toast(f"Ollama timeout on attempt {attempt}/{retries+1}, retrying...")
                continue
        except json.JSONDecodeError as e:
            last_err = e
            break
        except Exception as e:
            last_err = e
            break
    raise last_err or RuntimeError("Ollama batch failed after retries")

def ollama_detect_pii_columns(df: pd.DataFrame, base_url: str, model: str,
                               timeout: int = 180, batch_size: int = 10) -> list[str]:
    all_cols = list(df.columns)
    pii_cols = []
    batches  = [all_cols[i:i + batch_size] for i in range(0, len(all_cols), batch_size)]
    for idx, batch_cols in enumerate(batches, start=1):
        samples = {col: df[col].dropna().astype(str).head(3).tolist() for col in batch_cols}
        try:
            pii_cols.extend(_call_ollama_batch(samples, base_url, model, timeout))
        except Exception as e:
            st.warning(f"  Batch {idx}/{len(batches)} failed: {e}. Skipping.")
    return list(dict.fromkeys(pii_cols))

def cortex_detect_pii_columns(df: pd.DataFrame, conn, model: str, batch_size: int = 10) -> list[str]:
    """
    Detect PII columns using Snowflake Cortex AI (COMPLETE function).
    Sends column samples directly to Cortex via the active Snowflake connection.
    """
    all_cols = list(df.columns)
    pii_cols = []
    batches  = [all_cols[i:i + batch_size] for i in range(0, len(all_cols), batch_size)]
    cur = conn.cursor()

    for idx, batch_cols in enumerate(batches, start=1):
        samples = {col: df[col].dropna().astype(str).head(3).tolist() for col in batch_cols}
        prompt  = build_prompt(json.dumps(samples, indent=2)).replace("'", "\'")
        try:
            cur.execute(f"SELECT SNOWFLAKE.CORTEX.COMPLETE('{model}', '{prompt}')")
            row = cur.fetchone()
            raw = (row[0] if row else "").strip()
            raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
            result = json.loads(raw)
            if isinstance(result, list):
                pii_cols.extend([c for c in result if c in samples])
        except json.JSONDecodeError as e:
            st.warning(f"  Cortex batch {idx}/{len(batches)} returned unparseable JSON: {e}. Skipping.")
        except Exception as e:
            st.warning(f"  Cortex batch {idx}/{len(batches)} failed: {e}. Skipping.")

    return list(dict.fromkeys(pii_cols))


def regex_detect_pii_columns(df: pd.DataFrame) -> list[str]:
    hits = []
    for col in df.columns:
        series = df[col].astype(str)
        for pattern in REGEX_PATTERNS.values():
            if series.str.contains(pattern, regex=True, na=False).any():
                hits.append(col)
                break
    return hits

# ─── Data sources ─────────────────────────────────────────────────────────────

@st.cache_resource
def get_snowflake_conn(account, user, password, warehouse, database, schema, role):
    return connect(account=account, user=user, password=password,
                   warehouse=warehouse, database=database, schema=schema,
                   role=role or None)

def snowflake_fetch_tables(conn, database, schema):
    cur = conn.cursor()
    cur.execute(f"SHOW TABLES IN {database}.{schema}")
    return [r[1] for r in cur.fetchall()]

def snowflake_fetch_data(conn, database, schema, table, limit):
    cur = conn.cursor()
    cur.execute(f'SELECT * FROM "{database}"."{schema}"."{table}" LIMIT {limit}')
    return cur.fetch_pandas_all()

def snowflake_create_clone_schema(conn, src_db, src_schema, tgt_db, tgt_schema,
                                   table_masked_map: dict):
    """Create target schema and write masked tables into Snowflake."""
    cur = conn.cursor()
    cur.execute(f'CREATE DATABASE IF NOT EXISTS "{tgt_db}"')
    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{tgt_db}"."{tgt_schema}"')
    from snowflake.connector.pandas_tools import write_pandas
    results = {}
    for table_name, masked_df in table_masked_map.items():
        try:
            success, _, nrows, _ = write_pandas(
                conn, masked_df,
                table_name=table_name.upper(),
                database=tgt_db,
                schema=tgt_schema,
                auto_create_table=True,
                overwrite=True,
            )
            results[table_name] = f"✅ {nrows} rows written"
        except Exception as e:
            results[table_name] = f"❌ {e}"
    return results

@st.cache_resource
def get_sqlserver_engine(server, database, username, password, driver):
    if username and password:
        conn_str = (f"mssql+pyodbc://{username}:{password}@{server}/{database}"
                    f"?driver={driver.replace(' ', '+')}")
    else:
        conn_str = (f"mssql+pyodbc://@{server}/{database}"
                    f"?driver={driver.replace(' ', '+')}&trusted_connection=yes")
    return create_engine(conn_str)

def sqlserver_fetch_tables(engine):
    return inspect(engine).get_table_names()

def sqlserver_fetch_data(engine, table, limit):
    return pd.read_sql(f"SELECT TOP {limit} * FROM [{table}]", engine)

def sqlserver_create_clone_db(engine, tgt_db: str, table_masked_map: dict):
    """Create a new SQL Server database and write masked tables into it."""
    results = {}
    with engine.connect() as con:
        con.execute(text("COMMIT"))
        try:
            con.execute(text(f"IF DB_ID('{tgt_db}') IS NULL CREATE DATABASE [{tgt_db}]"))
        except Exception as e:
            return {t: f"❌ Could not create DB: {e}" for t in table_masked_map}

    tgt_url = str(engine.url).rsplit("/", 1)[0] + f"/{tgt_db}"
    tgt_engine = create_engine(tgt_url)
    for table_name, masked_df in table_masked_map.items():
        try:
            masked_df.to_sql(table_name, tgt_engine, if_exists="replace", index=False)
            results[table_name] = f"✅ {len(masked_df)} rows written"
        except Exception as e:
            results[table_name] = f"❌ {e}"
    return results

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    # ── User info & logout ────────────────────────────────────────────────────
    current_user = st.session_state.get("current_user", "")
    role_label   = ROLE_LABELS.get(current_user, current_user.capitalize())
    st.markdown(
        f"<div style='padding:8px 0 4px 0'>"
        f"<span style='font-size:18px'>👤</span> "
        f"<b>{current_user}</b> "
        f"<span style='color:#7FA2C8;font-size:12px'>({role_label})</span>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("🚪 Log Out", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    st.divider()
    st.header("1. Data Source")
    source_type = st.radio("Select data source",
                           ["Snowflake", "SQL Server", "CSV Upload"])
    st.divider()

    if source_type == "Snowflake":
        st.subheader("Snowflake Connection")
        sf_account   = st.text_input("Account identifier", placeholder="xy12345.us-east-1")
        sf_user      = st.text_input("Username")
        sf_password  = st.text_input("Password", type="password")
        sf_warehouse = st.text_input("Warehouse", placeholder="COMPUTE_WH")
        sf_database  = st.text_input("Database")
        sf_schema    = st.text_input("Schema", value="PUBLIC")
        sf_role      = st.text_input("Role (optional)")

    elif source_type == "SQL Server":
        st.subheader("SQL Server Connection")
        sql_server   = st.text_input("Server", placeholder="localhost\\SQLEXPRESS")
        sql_database = st.text_input("Database")
        sql_username = st.text_input("Username (blank = Windows auth)")
        sql_password = st.text_input("Password", type="password")
        available_drivers = [d for d in pyodbc.drivers() if "SQL Server" in d] or ["ODBC Driver 17 for SQL Server"]
        sql_driver   = st.selectbox("ODBC Driver", available_drivers)

    elif source_type == "CSV Upload":
        st.subheader("CSV Upload")
        uploaded_file = st.file_uploader("Upload CSV file(s)", type=["csv"], accept_multiple_files=True)
        csv_separator = st.selectbox("Delimiter", [",", ";", "\t", "|"])
        csv_encoding  = st.selectbox("Encoding", ["utf-8", "latin-1", "utf-16"])

    st.divider()
    st.subheader("2. AI Detection Engine")

    ai_engine = st.radio(
        "Select AI engine",
        ["Ollama (LLaMA)", "Snowflake Cortex"],
        horizontal=True,
        help="Ollama runs locally. Snowflake Cortex can be used with any data source.",
    )

    if ai_engine == "Ollama (LLaMA)":
        ollama_url     = st.text_input("Ollama base URL", value="http://localhost:11434")
        ollama_model   = st.text_input("Model", value="llama3")
        ollama_timeout = st.number_input("Timeout (s)", min_value=30, max_value=600, value=180, step=30)
        ollama_batch   = st.number_input("Columns per batch", min_value=1, max_value=30, value=10)
        cortex_model   = None
        cortex_account = cortex_user = cortex_password = cortex_warehouse = None
    else:
        cortex_model = st.selectbox(
            "Cortex model",
            ["mistral-large2", "llama3.1-70b", "llama3.1-8b", "snowflake-arctic", "mixtral-8x7b"],
            help="Must be available in your Snowflake account & region.",
        )
        ollama_batch = st.number_input("Columns per batch", min_value=1, max_value=30, value=10)
        ollama_url = ollama_model = None
        ollama_timeout = 180

        # If data source is already Snowflake, reuse that connection — no extra fields needed
        if source_type == "Snowflake":
            st.info("✅ Cortex will use your Snowflake data source connection.")
            cortex_account = cortex_user = cortex_password = cortex_warehouse = None
        else:
            st.info("Enter Snowflake credentials below to connect Cortex for AI detection.")
            cortex_account   = st.text_input("Cortex: Account identifier", placeholder="xy12345.us-east-1", key="cx_account")
            cortex_user      = st.text_input("Cortex: Username", key="cx_user")
            cortex_password  = st.text_input("Cortex: Password", type="password", key="cx_password")
            cortex_warehouse = st.text_input("Cortex: Warehouse", placeholder="COMPUTE_WH", key="cx_warehouse")

    st.divider()
    st.subheader("3. Fetch Settings")
    row_limit = st.number_input("Row limit per table", min_value=1, max_value=100_000, value=500)

    connect_btn = st.button(
        "Connect" if source_type != "CSV Upload" else "Load Files",
        use_container_width=True, type="primary"
    )

# ─── Session state ────────────────────────────────────────────────────────────

defaults = {
    "connection": None, "source_type": None, "tables": [],
    "selected_tables": [], "table_dfs": {},
    "table_pii_cols": {},   # {table: [detected pii cols]}
    "table_final_cols": {}, # {table: [user-confirmed cols]}
    "table_masked_dfs": {}, # {table: masked df}
    "detection_done": False,
    "faker_maps": {},         # {table: {col: faker_fn}}
    "faker_mapped": False,
    "faker_dfs": {},          # {table: generated fake df}
    "faker_mode": "replace",  # "replace" or "append"
    "fake_row_overrides": {}, # {table: int}  per-table row counts
    "active_output": None,    # "masked" or "fake" — drives Step 4
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Reset when source type switches
if st.session_state.source_type != source_type:
    for k, v in defaults.items():
        st.session_state[k] = v
    st.session_state.source_type = source_type

# ─── Step 1: Connect ──────────────────────────────────────────────────────────

if connect_btn:
    for k in ("tables", "selected_tables", "table_dfs", "table_pii_cols",
              "table_final_cols", "table_masked_dfs", "detection_done"):
        st.session_state[k] = [] if k in ("tables", "selected_tables") else ({} if k not in ("detection_done",) else False)

    if source_type == "Snowflake":
        with st.spinner("Connecting to Snowflake..."):
            try:
                conn = get_snowflake_conn(sf_account, sf_user, sf_password,
                                          sf_warehouse, sf_database, sf_schema, sf_role)
                st.session_state.connection = ("snowflake", conn, sf_database, sf_schema)
                st.session_state.tables     = snowflake_fetch_tables(conn, sf_database, sf_schema)
                st.success(f"Connected! Found {len(st.session_state.tables)} tables.")
            except Exception as e:
                st.error(f"Snowflake connection failed: {e}")

    elif source_type == "SQL Server":
        with st.spinner("Connecting to SQL Server..."):
            try:
                engine = get_sqlserver_engine(sql_server, sql_database, sql_username, sql_password, sql_driver)
                with engine.connect(): pass
                st.session_state.connection = ("sqlserver", engine)
                st.session_state.tables     = sqlserver_fetch_tables(engine)
                st.success(f"Connected! Found {len(st.session_state.tables)} tables.")
            except Exception as e:
                st.error(f"SQL Server connection failed: {e}")

    elif source_type == "CSV Upload":
        if not uploaded_file:
            st.error("Please upload at least one CSV file.")
        else:
            loaded = {}
            for f in uploaded_file:
                try:
                    loaded[f.name] = pd.read_csv(f, sep=csv_separator, encoding=csv_encoding)
                except Exception as e:
                    st.error(f"Failed to read {f.name}: {e}")
            if loaded:
                st.session_state.connection = ("csv", None)
                st.session_state.tables     = list(loaded.keys())
                st.session_state.table_dfs  = loaded
                st.success(f"Loaded {len(loaded)} file(s): {', '.join(loaded.keys())}")

# ─── Step 2: Table Selection ──────────────────────────────────────────────────

if st.session_state.connection and st.session_state.tables:
    st.divider()
    st.header("Step 2 — Select Tables")

    tables = st.session_state.tables

    # Select All / Deselect All buttons
    col_a, col_b, col_c = st.columns([1.2, 1.5, 7])
    with col_a:
        if st.button("☑ Select All", use_container_width=True):
            st.session_state.selected_tables = list(tables)
            for tbl in tables:
                st.session_state[f"chk_{tbl}"] = True
            st.rerun()
    with col_b:
        if st.button("☐ Deselect All", use_container_width=True):
            st.session_state.selected_tables = []
            for tbl in tables:
                st.session_state[f"chk_{tbl}"] = False
            st.rerun()

    # Build per-table checkboxes in a grid (4 columns)
    checked = {}
    cols_grid = st.columns(4)
    for i, tbl in enumerate(tables):
        with cols_grid[i % 4]:
            checked[tbl] = st.checkbox(tbl, key=f"chk_{tbl}")

    st.session_state.selected_tables = [t for t, v in checked.items() if v]

    if st.session_state.selected_tables:
        st.caption(f"{len(st.session_state.selected_tables)} table(s) selected: "
                   f"`{'`, `'.join(st.session_state.selected_tables)}`")

    btn_col1, btn_col2 = st.columns([2, 2])
    with btn_col1:
        fetch_detect_btn = st.button(
            f"🔍 Fetch & Detect PII — {len(st.session_state.selected_tables)} table(s)",
            type="primary",
            disabled=not st.session_state.selected_tables,
            use_container_width=True,
        )
    with btn_col2:
        fetch_fake_btn = st.button(
            f"🎭 Fetch & Generate Fake Data — {len(st.session_state.selected_tables)} table(s)",
            type="primary",
            disabled=not st.session_state.selected_tables,
            use_container_width=True,
        )

    # ── Fetch & Detect ────────────────────────────────────────────────────────
    if fetch_detect_btn:
        # Preserve pre-loaded CSV data before clearing state
        _saved_csv_dfs = {
            k: v for k, v in st.session_state.table_dfs.items()
        } if st.session_state.connection and st.session_state.connection[0] == "csv" else {}

        st.session_state.table_dfs        = _saved_csv_dfs  # restore CSV data, empty for DB sources
        st.session_state.table_pii_cols   = {}
        st.session_state.table_final_cols = {}
        st.session_state.table_masked_dfs = {}
        st.session_state.detection_done   = False

        conn_type = st.session_state.connection[0]
        total_tables = len(st.session_state.selected_tables)

        overall_bar = st.progress(0, text="Starting...")
        for t_idx, table in enumerate(st.session_state.selected_tables):
            overall_bar.progress(t_idx / total_tables, text=f"Processing `{table}` ({t_idx+1}/{total_tables})...")

            # Fetch
            with st.spinner(f"Fetching `{table}`..."):
                try:
                    if conn_type == "snowflake":
                        _, conn, db, sch = st.session_state.connection
                        df = snowflake_fetch_data(conn, db, sch, table, int(row_limit))
                    elif conn_type == "sqlserver":
                        _, engine = st.session_state.connection
                        df = sqlserver_fetch_data(engine, table, int(row_limit))
                    elif conn_type == "csv":
                        df = st.session_state.table_dfs.get(table, pd.DataFrame())
                    st.session_state.table_dfs[table] = df
                except Exception as e:
                    st.error(f"Failed to fetch `{table}`: {e}")
                    continue

            # Regex pre-screen
            regex_cols = regex_detect_pii_columns(df)

            # AI detection (Ollama or Cortex)
            if ai_engine == "Ollama (LLaMA)":
                with st.spinner(f"Asking Ollama ({ollama_model}) about `{table}`..."):
                    try:
                        llm_cols = ollama_detect_pii_columns(
                            df, ollama_url, ollama_model,
                            timeout=int(ollama_timeout), batch_size=int(ollama_batch)
                        )
                    except Exception as e:
                        st.warning(f"Ollama failed for `{table}`: {e}. Using regex only.")
                        llm_cols = []
            else:
                # Resolve Snowflake connection for Cortex:
                # - If data source is Snowflake, reuse that connection
                # - Otherwise use the separately entered Cortex credentials
                if st.session_state.connection and st.session_state.connection[0] == "snowflake":
                    sf_conn_for_cortex = st.session_state.connection[1]
                elif cortex_account and cortex_user and cortex_password:
                    try:
                        sf_conn_for_cortex = st.session_state.get("cortex_conn") or connect(
                            account=cortex_account, user=cortex_user,
                            password=cortex_password, warehouse=cortex_warehouse or "",
                        )
                        st.session_state["cortex_conn"] = sf_conn_for_cortex
                    except Exception as e:
                        st.warning(f"Could not connect to Snowflake for Cortex: {e}. Falling back to regex only.")
                        sf_conn_for_cortex = None
                else:
                    st.warning("Snowflake Cortex credentials are incomplete. Falling back to regex only.")
                    sf_conn_for_cortex = None

                if sf_conn_for_cortex is None:
                    llm_cols = []
                else:
                    with st.spinner(f"Asking Snowflake Cortex ({cortex_model}) about `{table}`..."):
                        try:
                            llm_cols = cortex_detect_pii_columns(
                                df, sf_conn_for_cortex, cortex_model, batch_size=int(ollama_batch)
                            )
                        except Exception as e:
                            st.warning(f"Cortex failed for `{table}`: {e}. Using regex only.")
                            llm_cols = []

            combined = list(dict.fromkeys(llm_cols + regex_cols))
            st.session_state.table_pii_cols[table]   = combined
            st.session_state.table_final_cols[table] = combined  # editable copy
            # Pre-populate the multiselect widget key so default= is honoured on all reruns
            st.session_state[f"final_{table}"] = [c for c in combined if c in df.columns]

        overall_bar.progress(1.0, text="Detection complete!")
        st.session_state.detection_done = True
        st.session_state.active_output  = "masked"
        st.rerun()

    # ── Fetch & Generate Fake Data ────────────────────────────────────────────
    if fetch_fake_btn:
        # Preserve pre-loaded CSV data
        _saved_csv_dfs2 = {
            k: v for k, v in st.session_state.table_dfs.items()
        } if st.session_state.connection and st.session_state.connection[0] == "csv" else {}

        st.session_state.table_dfs        = _saved_csv_dfs2
        st.session_state.faker_maps       = {}
        st.session_state.faker_mapped     = False
        st.session_state.faker_dfs        = {}
        st.session_state.fake_row_overrides = {}
        st.session_state.table_masked_dfs = {}
        st.session_state.detection_done   = False

        conn_type2 = st.session_state.connection[0]

        # Resolve AI for faker column mapping
        if ai_engine == "Ollama (LLaMA)":
            _fai_engine2, _fai_sf_conn2 = "Ollama (LLaMA)", None
        else:
            _fai_engine2 = "Snowflake Cortex"
            if st.session_state.connection and st.session_state.connection[0] == "snowflake":
                _fai_sf_conn2 = st.session_state.connection[1]
            elif st.session_state.get("cortex_conn"):
                _fai_sf_conn2 = st.session_state["cortex_conn"]
            else:
                _fai_sf_conn2 = None

        fake_bar = st.progress(0, text="Starting...")
        for t_idx, table in enumerate(st.session_state.selected_tables):
            fake_bar.progress(t_idx / len(st.session_state.selected_tables),
                              text=f"Fetching & mapping `{table}` ({t_idx+1}/{len(st.session_state.selected_tables)})...")
            # Fetch
            try:
                if conn_type2 == "snowflake":
                    _, conn2, db2, sch2 = st.session_state.connection
                    df2 = snowflake_fetch_data(conn2, db2, sch2, table, int(row_limit))
                elif conn_type2 == "sqlserver":
                    _, engine2 = st.session_state.connection
                    df2 = sqlserver_fetch_data(engine2, table, int(row_limit))
                elif conn_type2 == "csv":
                    df2 = st.session_state.table_dfs.get(table, pd.DataFrame())
                st.session_state.table_dfs[table] = df2
            except Exception as e:
                st.error(f"Failed to fetch `{table}`: {e}")
                continue

            # Default row count = actual table row count
            st.session_state.fake_row_overrides[table] = len(df2)

            # AI column mapping — pass sample values for better accuracy
            fmap = ai_map_faker_columns(
                list(df2.columns), _fai_engine2,
                df_sample=df2,
                ollama_url=ollama_url, ollama_model=ollama_model,
                ollama_timeout=int(ollama_timeout),
                sf_conn=_fai_sf_conn2, cortex_model=cortex_model,
            )
            st.session_state.faker_maps[table] = fmap

        fake_bar.progress(1.0, text="Mapping complete!")
        st.session_state.faker_mapped     = True
        st.session_state.active_output    = "fake"
        st.rerun()

# ─── Step 3: Review PII per Table ─────────────────────────────────────────────

if st.session_state.detection_done and st.session_state.table_pii_cols:
    st.divider()
    st.header("Step 3 — Review & Finalize PII Columns")
    st.markdown(
        "Ollama has pre-selected the PII columns per table. "
        "**Add or remove** columns for each table as needed."
    )

    for table in st.session_state.selected_tables:
        df      = st.session_state.table_dfs.get(table, pd.DataFrame())
        detected = st.session_state.table_pii_cols.get(table, [])

        with st.expander(
            f"📋 **{table}** — {len(detected)} PII column(s) detected  "
            f"| {len(df):,} rows × {len(df.columns)} cols",
            expanded=True,
        ):
            # Widget key drives pre-selection (set during detection); read back after user edits
            final_cols = st.multiselect(
                "PII columns to mask",
                options=list(df.columns),
                key=f"final_{table}",
                help="Pre-populated by AI + regex. Add or remove freely.",
            )
            st.session_state.table_final_cols[table] = final_cols

            # Preview toggle (inline, compatible with all Streamlit versions)
            if final_cols:
                if st.button(f"👁️ Preview Masking", key=f"prev_btn_{table}"):
                    st.session_state[f"show_preview_{table}"] = not st.session_state.get(f"show_preview_{table}", False)

                if st.session_state.get(f"show_preview_{table}", False):
                    with st.container(border=True):
                        st.markdown(f"**Masking Preview — `{table}`** *(first 10 rows of selected PII columns)*")
                        orig   = df[final_cols].head(10)
                        masked = orig.apply(mask_column)
                        t1, t2 = st.tabs(["Original", "Masked"])
                        with t1: st.dataframe(orig, use_container_width=True)
                        with t2: st.dataframe(masked, use_container_width=True)

    # ── Apply masking button ──────────────────────────────────────────────────
    st.divider()
    any_cols = any(cols for cols in st.session_state.table_final_cols.values())
    if st.button("🔒 Apply Masking to All Tables", type="primary", disabled=not any_cols):
        masked_map = {}
        for table in st.session_state.selected_tables:
            df   = st.session_state.table_dfs.get(table, pd.DataFrame())
            cols = st.session_state.table_final_cols.get(table, [])
            masked_map[table] = mask_dataframe(df, cols)
        st.session_state.table_masked_dfs = masked_map
        st.session_state.active_output    = "masked"
        st.success("✅ Masking applied to all tables!")
        st.rerun()

# ─── Step 3b: Fake Data Review & Generate ─────────────────────────────────────

if st.session_state.faker_mapped and st.session_state.faker_maps:
    st.divider()
    st.header("Step 3 — Review & Generate Fake Data")
    st.markdown(
        "AI has mapped each column to a Faker method. "
        "**Edit mappings** and set **row counts per table**, then click Generate."
    )

    # ── Global mode ──────────────────────────────────────────────────────────
    g1, g2 = st.columns([3, 2])
    with g1:
        fake_mode = st.radio(
            "Generation mode",
            ["Replace all data with fake data", "Append fake rows to existing data"],
            key="fake_mode_radio",
            horizontal=True,
            help="Replace: discard originals entirely. Append: add fake rows below original data.",
        )
    with g2:
        st.caption("Per-table row counts are set inside each table expander below.")

    FAKER_OPTIONS = sorted([
        "name","first_name","last_name","email","phone_number","ssn",
        "address","street_address","city","state","zipcode","postcode",
        "country","company","user_name","password","ipv4","ipv6","url",
        "date_of_birth","date","credit_card_number","iban","bban",
        "text","sentence","word","uuid4","job","latitude","longitude",
        "random_int","pyfloat","random_element",
    ])

    updated_maps = {}
    for table in st.session_state.selected_tables:
        fmap = st.session_state.faker_maps.get(table, {})
        if not fmap:
            continue
        df_t          = st.session_state.table_dfs.get(table, pd.DataFrame())
        default_rows  = st.session_state.fake_row_overrides.get(table, len(df_t))

        with st.expander(
            f"📋 **{table}** — {len(fmap)} columns | original {len(df_t):,} rows",
            expanded=True,
        ):
            # Per-table row count control
            rc_col, _ = st.columns([2, 4])
            with rc_col:
                tbl_rows = st.number_input(
                    "Rows to generate",
                    min_value=1, max_value=1_000_000,
                    value=int(default_rows),
                    key=f"rows_{table}",
                    help=f"Default = original row count ({len(df_t):,})",
                )
            st.session_state.fake_row_overrides[table] = int(tbl_rows)

            # Column → Faker mapping grid (3 columns)
            updated_maps[table] = {}
            cols_list = list(fmap.keys())
            grid = st.columns(3)
            for ci, col in enumerate(cols_list):
                with grid[ci % 3]:
                    current = fmap[col] if fmap[col] in FAKER_OPTIONS else FAKER_OPTIONS[0]
                    chosen  = st.selectbox(
                        col, FAKER_OPTIONS,
                        index=FAKER_OPTIONS.index(current),
                        key=f"fmap_{table}_{col}",
                    )
                    updated_maps[table][col] = chosen

    # Persist edits
    for table, fmap in updated_maps.items():
        st.session_state.faker_maps[table] = fmap

    st.divider()
    if st.button("✨ Generate Fake Data for All Tables", type="primary", key="faker_gen_btn"):
        st.session_state.faker_dfs = {}
        gen_prog = st.progress(0, text="Generating...")
        tables_list = st.session_state.selected_tables
        for i, table in enumerate(tables_list):
            gen_prog.progress(i / len(tables_list), text=f"Generating `{table}`...")
            df_t   = st.session_state.table_dfs.get(table, pd.DataFrame())
            fmap   = st.session_state.faker_maps.get(table, {})
            n_rows = st.session_state.fake_row_overrides.get(table, len(df_t))
            if not fmap:
                continue
            fake_df = generate_fake_dataframe(list(df_t.columns), fmap, df_t, int(n_rows))
            if fake_mode == "Append fake rows to existing data" and not df_t.empty:
                result_df = pd.concat([df_t, fake_df], ignore_index=True)
            else:
                result_df = fake_df
            st.session_state.faker_dfs[table] = result_df
        gen_prog.progress(1.0, text="Done!")
        st.session_state.active_output = "fake"
        st.rerun()

    # Preview
    if st.session_state.faker_dfs:
        st.subheader("Preview Generated Fake Data")
        for table, fdf in st.session_state.faker_dfs.items():
            with st.expander(f"📋 **{table}** — {len(fdf):,} rows", expanded=False):
                st.dataframe(fdf.head(20), use_container_width=True)

# ─── Step 4: Export (masked OR fake, whichever was last generated) ────────────

_has_output = bool(st.session_state.table_masked_dfs or st.session_state.faker_dfs)
_output_type = st.session_state.get("active_output")  # "masked" or "fake"

if _has_output and _output_type:
    st.divider()
    _label = "Masked Data" if _output_type == "masked" else "Fake Data"
    _export_dfs = st.session_state.table_masked_dfs if _output_type == "masked" else st.session_state.faker_dfs
    _file_prefix = "masked" if _output_type == "masked" else "fake"
    _zip_name    = "masked_tables.zip" if _output_type == "masked" else "fake_tables.zip"

    st.header(f"Step 4 — Export {_label}")
    conn_type = st.session_state.connection[0] if st.session_state.connection else "csv"

    tab_csv, tab_clone = st.tabs(["📥 Download CSVs", "🗄️ Clone to Database"])

    # ── Download CSVs ─────────────────────────────────────────────────────────
    with tab_csv:
        st.markdown(f"Download individual CSVs or a single ZIP of all {_label.lower()}.")
        st.subheader("Individual tables")
        dl_cols = st.columns(min(len(_export_dfs), 4))
        for i, (table, edf) in enumerate(_export_dfs.items()):
            buf = io.BytesIO()
            edf.to_csv(buf, index=False)
            with dl_cols[i % 4]:
                st.download_button(
                    label=f"⬇️ {table}.csv",
                    data=buf.getvalue(),
                    file_name=f"{_file_prefix}_{table}.csv",
                    mime="text/csv",
                    key=f"dl4_{table}",
                )
        st.subheader("All tables as ZIP")
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for table, edf in _export_dfs.items():
                zf.writestr(f"{_file_prefix}_{table}.csv", edf.to_csv(index=False).encode("utf-8"))
        st.download_button(
            label=f"⬇️ Download All as ZIP",
            data=zip_buf.getvalue(),
            file_name=_zip_name,
            mime="application/zip",
            key="dl4_zip",
        )

    # ── Clone to Database ─────────────────────────────────────────────────────
    with tab_clone:
        if conn_type == "csv":
            st.info("Clone to database is not available for CSV uploads. Use the Download tab.")
        else:
            st.markdown(
                f"Write all {_label.lower()} into a **new database/schema** on the same server, "
                "leaving the original data untouched."
            )
            _default_suffix = "_MASKED" if _output_type == "masked" else "_FAKE"
            if conn_type == "snowflake":
                _, conn_w, src_db, src_schema = st.session_state.connection
                c1, c2 = st.columns(2)
                with c1: tgt_db     = st.text_input("Target Database", value=f"{src_db}{_default_suffix}", key="tgt_db4")
                with c2: tgt_schema = st.text_input("Target Schema",   value=src_schema,                   key="tgt_sch4")
                if st.button(f"🚀 Write {_label} to Snowflake", type="primary", key="write4_sf"):
                    with st.spinner("Writing to Snowflake..."):
                        results = snowflake_create_clone_schema(conn_w, src_db, src_schema, tgt_db, tgt_schema, _export_dfs)
                    for tbl, msg in results.items():
                        st.write(f"**{tbl}**: {msg}")
            elif conn_type == "sqlserver":
                _, engine_w = st.session_state.connection
                src_db = str(engine_w.url).rsplit("/", 1)[-1]
                tgt_db = st.text_input("Target Database", value=f"{src_db}{_default_suffix}", key="tgt_db4_sql")
                if st.button(f"🚀 Write {_label} to SQL Server", type="primary", key="write4_sql"):
                    with st.spinner("Writing to SQL Server..."):
                        results = sqlserver_create_clone_db(engine_w, tgt_db, _export_dfs)
                    for tbl, msg in results.items():
                        st.write(f"**{tbl}**: {msg}")

elif st.session_state.connection is None:
    st.info("👈 Select a data source in the sidebar and click Connect to begin.")
