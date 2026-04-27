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
from urllib.parse import quote_plus
from faker import Faker
from faker.providers import internet, person, address, phone_number, company, date_time, bank, misc
import factory
from factory import fuzzy as factory_fuzzy
from sqlalchemy import create_engine, inspect, text
from snowflake.connector import connect


# ─── Auth configuration ───────────────────────────────────────────────────────
# Users are loaded from st.secrets (Streamlit Cloud) or from a local
# .streamlit/secrets.toml file in the repo.
#
# secrets.toml format:
#
#   [users.admin]
#   password = "your_plain_text_password"
#   role     = "Administrator"
#
#   [users.analyst]
#   password = "analyst_password"
#   role     = "Data Analyst"
#
#   [users.viewer]
#   password = "viewer_password"
#   role     = "Viewer"
#
# Passwords in secrets.toml are stored as plain text but the file is never
# committed to the repo — add .streamlit/secrets.toml to .gitignore.
# On Streamlit Cloud, paste the same content into App Settings → Secrets.
#
# Alternatively, store pre-hashed passwords:
#   [users.admin]
#   password_hash = "sha256hexdigest..."
#   role          = "Administrator"
#
# Generate a hash: python -c "import hashlib; print(hashlib.sha256(b'pw').hexdigest())"

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _load_user_db() -> tuple[dict, dict]:
    """Load USER_DB and ROLE_LABELS from st.secrets.
    Falls back to hardcoded defaults if secrets are not configured,
    so the app still works during local development without a secrets file.
    """
    user_db     = {}
    role_labels = {}
    try:
        users_cfg = st.secrets.get("users", {})
        if not users_cfg:
            raise KeyError("no [users] section in secrets")
        for username, cfg in users_cfg.items():
            uname = username.strip().lower()
            # Support both pre-hashed and plain-text passwords
            if "password_hash" in cfg:
                user_db[uname] = cfg["password_hash"]
            elif "password" in cfg:
                user_db[uname] = _hash(cfg["password"])
            else:
                continue  # skip entries with no password
            role_labels[uname] = cfg.get("role", uname.capitalize())
    except Exception:
        # Fallback defaults for local dev when no secrets.toml exists
        # Change or remove these before deploying to production
        user_db = {
            "admin":   _hash("admin123"),
            "analyst": _hash("analyst@2024"),
            "viewer":  _hash("view#only1"),
        }
        role_labels = {
            "admin":   "Administrator",
            "analyst": "Data Analyst",
            "viewer":  "Viewer",
        }
    return user_db, role_labels

# Load once at startup
USER_DB, ROLE_LABELS = _load_user_db()

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
        st.image("https://img.icons8.com/fluency/96/dna.png", width=72)
        st.markdown("## 🧬 IntelliClone")
        st.markdown("##### Intelligent Data Masking & Demo Data Generation")
        st.markdown("###### Please log in to continue")
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
    st.set_page_config(page_title="IntelliClone — Login", layout="centered")
    _render_login()
    st.stop()

st.set_page_config(page_title="IntelliClone", layout="wide")
st.title("🧬 IntelliClone")
st.markdown("Connect to a data source, auto-detect PII columns with Ollama, review, then mask or clone with demo data.")

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
#
# DESIGN: _profile_column() is the single source of truth about a column.
# Everything downstream — generator selection, dtype casting, range bounds —
# reads exclusively from the profile dict. No other code inspects raw data.
# ─────────────────────────────────────────────────────────────────────────────

import datetime as _dt
import random   as _rnd

def _profile_column(series: pd.Series) -> dict:
    """Return a profile dict describing the column's shape, type, and statistics.

    Keys set (where applicable):
      kind          : "int" | "float" | "bool" | "datetime" | "date_str" |
                      "numeric_str" | "pattern" | "enum" | "text" | "string"
      dtype_str     : str(series.dtype)
      nullable      : bool
      null_rate     : float 0-1
      min_val/max_val: numeric bounds (int/float columns and numeric_str)
      decimal_places: int (float columns)
      true_ratio    : float (bool columns)
      date_fmt      : strftime format string
      date_min/max  : "YYYY-MM-DD" strings (date_str and datetime)
      time_varies   : bool (datetime — False means midnight-only)
      pattern_template: bothify template string e.g. "POL-####-######"
      pattern_prefix: fixed literal prefix e.g. "POL-"
      enum_values   : list of observed values
      enum_weights  : list of floats summing to 1.0
      min_len/max_len: string length bounds
      sample_values : up to 8 raw sample strings (for Cortex prompts)
    """
    profile = {
        "kind":      "string",
        "dtype_str": str(series.dtype),
        "nullable":  False,
        "null_rate": 0.0,
    }

    n_total  = len(series)
    non_null = series.dropna()
    n_valid  = len(non_null)

    if n_total > 0:
        profile["null_rate"] = float(series.isna().mean())
        profile["nullable"]  = profile["null_rate"] > 0.0

    if n_valid == 0:
        return profile

    profile["sample_values"] = non_null.astype(str).head(8).tolist()
    dtype_str = str(series.dtype)

    # ── Integer / Float ───────────────────────────────────────────────────────
    if "int" in dtype_str:
        profile["kind"]    = "int"
        profile["min_val"] = int(non_null.min())
        profile["max_val"] = int(non_null.max())
        return profile

    if "float" in dtype_str:
        profile["kind"]    = "float"
        profile["min_val"] = float(non_null.min())
        profile["max_val"] = float(non_null.max())
        # Median decimal precision across non-null values
        dp_series = non_null.apply(
            lambda x: len(str(round(x, 10)).rstrip("0").split(".")[-1])
            if "." in str(round(x, 10)) else 0
        )
        profile["decimal_places"] = max(0, int(dp_series.median()))
        return profile

    # ── Boolean ───────────────────────────────────────────────────────────────
    if "bool" in dtype_str:
        profile["kind"]       = "bool"
        profile["true_ratio"] = float(non_null.mean())
        return profile

    # ── Datetime (pandas dtype) ───────────────────────────────────────────────
    if "datetime" in dtype_str:
        profile["kind"]    = "datetime"
        profile["min_val"] = str(non_null.min())
        profile["max_val"] = str(non_null.max())
        try:
            profile["date_min"] = str(non_null.min().date())
            profile["date_max"] = str(non_null.max().date())
        except Exception:
            pass
        # Does the time component ever vary?
        try:
            profile["time_varies"] = bool((non_null.dt.hour != 0).any() or
                                          (non_null.dt.minute != 0).any())
        except Exception:
            profile["time_varies"] = True
        return profile

    # ── String analysis ───────────────────────────────────────────────────────
    str_vals = non_null.astype(str).str.strip()
    lengths  = str_vals.str.len()
    profile["min_len"]  = int(lengths.min())
    profile["max_len"]  = int(lengths.max())
    profile["mean_len"] = int(lengths.mean())
    n_unique            = non_null.nunique()
    unique_ratio        = n_unique / n_valid

    # Priority 1 — Date string (check multiple samples, require ≥60% match)
    _DATE_FMTS = [
        "%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d",
        "%d-%m-%Y", "%m-%d-%Y", "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y", "%b %d, %Y", "%Y%m%d",
    ]
    samples10 = str_vals.head(10).tolist()
    date_fmt, date_hits = None, 0
    for sv in samples10:
        for fmt in _DATE_FMTS:
            try:
                pd.to_datetime(sv, format=fmt)
                date_hits += 1
                date_fmt = date_fmt or fmt
                break
            except Exception:
                pass
    if date_hits >= max(2, len(samples10) * 0.6):
        profile["kind"]     = "date_str"
        profile["date_fmt"] = date_fmt or "%Y-%m-%d"
        try:
            parsed = pd.to_datetime(str_vals, format=date_fmt, errors="coerce").dropna()
            if len(parsed):
                profile["date_min"] = str(parsed.min().date())
                profile["date_max"] = str(parsed.max().date())
        except Exception:
            pass
        return profile

    # Priority 2 — Pure numeric string
    num_coerced = pd.to_numeric(str_vals, errors="coerce")
    if num_coerced.notna().mean() > 0.85:
        profile["kind"]    = "numeric_str"
        profile["min_val"] = float(num_coerced.min())
        profile["max_val"] = float(num_coerced.max())
        # Leading zeros (e.g. "007", "00045")
        if str_vals.str.match(r"^0\d").any():
            profile["leading_zeros"] = True
            profile["fixed_len"]     = int(lengths.mode()[0])
        return profile

    # Priority 3 — Coded / patterned IDs  (e.g. "POL-2025-100003")
    def _shape(s):
        import re as _re2
        s = _re2.sub(r"[A-Za-z]+", "A", s)
        s = _re2.sub(r"[0-9]+",   "N", s)
        return s

    shapes     = str_vals.head(40).apply(_shape)
    top_shape  = shapes.value_counts().index[0]
    top_ratio  = shapes.value_counts().iloc[0] / len(shapes)

    if top_ratio >= 0.65 and re.search(r"[^AN]", top_shape):
        samples40 = str_vals.head(40).tolist()
        # Longest common prefix = fixed literal part
        prefix = samples40[0]
        for sv in samples40[1:]:
            while prefix and not sv.startswith(prefix):
                prefix = prefix[:-1]
        suffix_ex  = samples40[0][len(prefix):]
        tmpl_sfx   = re.sub(r"[A-Za-z]", "?", suffix_ex)
        tmpl_sfx   = re.sub(r"[0-9]",    "#", tmpl_sfx)
        full_tmpl  = prefix + tmpl_sfx
        if ("#" in tmpl_sfx or "?" in tmpl_sfx) and 2 <= len(full_tmpl) <= 50:
            profile["kind"]             = "pattern"
            profile["pattern_template"] = full_tmpl
            profile["pattern_prefix"]   = prefix
            return profile

    # Priority 4 — Enum / categorical  (≤25 distinct values, ≤70% unique ratio)
    if n_unique <= 25 and unique_ratio <= 0.70:
        vc = non_null.value_counts(normalize=True)
        profile["kind"]         = "enum"
        profile["enum_values"]  = vc.index.tolist()
        profile["enum_weights"] = [float(w) for w in vc.values.tolist()]
        return profile

    # Priority 5 — Free text (avg > 5 words)
    avg_words = sum(len(s.split()) for s in samples10) / max(len(samples10), 1)
    if avg_words > 5:
        profile["kind"] = "text"
        return profile

    # Default — generic string
    profile["kind"] = "string"
    return profile


# ─── Safe numeric ranges ──────────────────────────────────────────────────────

def _safe_int_range(mn, mx):
    mn, mx = int(mn), int(mx)
    return mn, max(mn + 1, mx)

def _safe_float_range(mn_f, mx_f):
    mn_f, mx_f = float(mn_f), float(mx_f)
    return mn_f, max(mn_f + 1.0, mx_f)


# ─── factory_boy entity factories ────────────────────────────────────────────

class _PersonFactory(factory.Factory):
    """All person fields derived from the same first+last name seed."""
    class Meta:
        model = dict

    first_name   = factory.Faker("first_name")
    last_name    = factory.Faker("last_name")
    prefix       = factory.Faker("prefix")
    suffix       = factory.Faker("suffix")
    ssn          = factory.Faker("ssn")
    job          = factory.Faker("job")
    phone_number = factory.Faker("phone_number")
    date_of_birth = factory.LazyAttribute(
        lambda o: _faker.date_of_birth(minimum_age=18, maximum_age=90).strftime("%Y-%m-%d")
    )
    name = factory.LazyAttribute(lambda o: f"{o.first_name} {o.last_name}")
    email = factory.LazyAttribute(lambda o: (
        re.sub(r"[^a-z]", "", o.first_name.lower()) +
        _rnd.choice([".", "_"]) +
        re.sub(r"[^a-z]", "", o.last_name.lower()) +
        (str(_faker.random_int(1, 99)) if _rnd.random() < 0.4 else "") +
        "@" + _faker.free_email_domain()
    ))
    user_name = factory.LazyAttribute(
        lambda o: re.sub(r"[^a-z0-9._]", "", o.email.split("@")[0].lower())[:28]
    )
    password = factory.LazyAttribute(
        lambda o: _faker.password(length=12, special_chars=True, digits=True, upper_case=True)
    )


class _AddressFactory(factory.Factory):
    """City/state/zip generated together so they are geographically coherent."""
    class Meta:
        model = dict

    street_address    = factory.Faker("street_address")
    secondary_address = factory.Faker("secondary_address")
    city              = factory.Faker("city")
    state_abbr        = factory.Faker("state_abbr")
    zipcode           = factory.Faker("zipcode")
    country           = "US"
    address = factory.LazyAttribute(
        lambda o: f"{o.street_address}, {o.city}, {o.state_abbr} {o.zipcode}"
    )
    postcode = factory.SelfAttribute("zipcode")
    state    = factory.SelfAttribute("state_abbr")


class _CompanyFactory(factory.Factory):
    class Meta:
        model = dict

    company = factory.Faker("company")
    company_email = factory.LazyAttribute(
        lambda o: "info@" + re.sub(r"[^a-z0-9]", "", o.company.lower()[:15]) + ".com"
    )


# ─── fuzzy helpers (factory_boy) ──────────────────────────────────────────────

def _fuzzy_int(mn: int, mx: int) -> int:
    return factory_fuzzy.FuzzyInteger(mn, mx).fuzz()

def _fuzzy_float(mn: float, mx: float, dp: int = 2) -> float:
    return round(factory_fuzzy.FuzzyFloat(mn, mx).fuzz(), dp)

def _fuzzy_date(start_str: str, end_str: str, fmt: str = "%Y-%m-%d") -> str:
    try:
        s = _dt.date.fromisoformat(start_str[:10])
        e = _dt.date.fromisoformat(end_str[:10])
        if s >= e:
            e = s + _dt.timedelta(days=365)
        return factory_fuzzy.FuzzyDate(s, e).fuzz().strftime(fmt)
    except Exception:
        return _faker.date_this_decade().strftime(fmt)

def _fuzzy_datetime(start_str: str, end_str: str, time_varies: bool = True):
    """Return a datetime object within [start, end]."""
    try:
        s = pd.to_datetime(start_str).to_pydatetime()
        e = pd.to_datetime(end_str).to_pydatetime()
        if s >= e:
            e = s + _dt.timedelta(days=365)
        return _faker.date_time_between(start_date=s, end_date=e)
    except Exception:
        return _faker.date_time_this_decade()

def _fuzzy_choice(vals: list, weights: list = None):
    if weights and len(weights) == len(vals):
        return _rnd.choices(vals, weights=weights, k=1)[0]
    return factory_fuzzy.FuzzyChoice(vals).fuzz()


# ─── Per-kind value generators ────────────────────────────────────────────────
#
# generate_value(kind, profile, faker_fn) is the single entry point.
# It dispatches purely on profile["kind"], making behaviour predictable.
# faker_fn is only consulted for the "string" kind (semantic Faker methods).

def _gen_int(profile: dict) -> int:
    mn, mx = _safe_int_range(profile.get("min_val", 0), profile.get("max_val", 99999))
    return _fuzzy_int(mn, mx)

def _gen_float(profile: dict) -> float:
    mn, mx = _safe_float_range(profile.get("min_val", 0.0), profile.get("max_val", 99999.0))
    dp     = profile.get("decimal_places", 2)
    return _fuzzy_float(mn, mx, dp)

def _gen_bool(profile: dict) -> bool:
    return _rnd.random() < profile.get("true_ratio", 0.5)

def _gen_datetime(profile: dict):
    dmin = profile.get("min_val") or profile.get("date_min", "2015-01-01")
    dmax = profile.get("max_val") or profile.get("date_max", "2025-12-31")
    dt   = _fuzzy_datetime(str(dmin), str(dmax), profile.get("time_varies", True))
    if not profile.get("time_varies", True):
        dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt

def _gen_date_str(profile: dict) -> str:
    fmt  = profile.get("date_fmt", "%Y-%m-%d")
    dmin = profile.get("date_min", "2015-01-01")
    dmax = profile.get("date_max", "2025-12-31")
    return _fuzzy_date(dmin, dmax, fmt)

def _gen_numeric_str(profile: dict) -> str:
    mn, mx = _safe_int_range(profile.get("min_val", 0), profile.get("max_val", 99999))
    val    = _fuzzy_int(mn, mx)
    if profile.get("leading_zeros") and profile.get("fixed_len"):
        return str(val).zfill(profile["fixed_len"])
    return str(val)

def _gen_pattern(profile: dict) -> str:
    tmpl = profile.get("pattern_template", "??-####")
    try:
        return _faker.bothify(text=tmpl)
    except Exception:
        return _faker.bothify(text="??-####")

def _gen_enum(profile: dict):
    return _fuzzy_choice(profile["enum_values"], profile.get("enum_weights"))

def _gen_text(_profile: dict) -> str:
    return _faker.sentence(nb_words=_rnd.randint(6, 14))

# Semantic Faker method dispatcher — used only for "string" kind
_SEMANTIC_MAP = {
    "first_name":          lambda p: None,    # handled by entity factory
    "last_name":           lambda p: None,
    "name":                lambda p: None,
    "email":               lambda p: None,
    "user_name":           lambda p: None,
    "phone_number":        lambda p: _faker.phone_number(),
    "ssn":                 lambda p: _faker.ssn(),
    "address":             lambda p: None,    # handled by entity factory
    "street_address":      lambda p: None,
    "city":                lambda p: None,
    "state_abbr":          lambda p: None,
    "zipcode":             lambda p: None,
    "country":             lambda p: None,
    "company":             lambda p: None,    # handled by entity factory
    "job":                 lambda p: _faker.job(),
    "uuid4":               lambda p: str(_faker.uuid4()),
    "ipv4":                lambda p: _faker.ipv4(),
    "ipv6":                lambda p: _faker.ipv6(),
    "url":                 lambda p: _faker.url(),
    "credit_card_number":  lambda p: _faker.credit_card_number(),
    "iban":                lambda p: _faker.iban(),
    "bban":                lambda p: _faker.bban(),
    "currency_code":       lambda p: _faker.currency_code(),
    "color_name":          lambda p: _faker.color_name(),
    "latitude":            lambda p: str(_faker.latitude()),
    "longitude":           lambda p: str(_faker.longitude()),
    "sentence":            lambda p: _faker.sentence(),
    "text":                lambda p: _faker.text(max_nb_chars=200),
    "paragraph":           lambda p: _faker.paragraph(),
    "word":                lambda p: _faker.word(),
    "password":            lambda p: _faker.password(length=12, special_chars=True),
    "prefix":              lambda p: _faker.prefix(),
    "suffix":              lambda p: _faker.suffix(),
    "year":                lambda p: str(_faker.year()),
    "time":                lambda p: _faker.time(),
    "locale":              lambda p: _faker.locale(),
}

def _gen_string(profile: dict, faker_fn: str) -> str:
    """Generate a string value using the semantic Faker method."""
    if faker_fn.startswith("__pattern__"):
        return _faker.bothify(text=faker_fn[len("__pattern__"):])

    handler = _SEMANTIC_MAP.get(faker_fn)
    if handler is not None:
        result = handler(profile)
        if result is not None:
            return str(result)

    # Try calling Faker directly as a fallback
    try:
        fn_callable = getattr(_faker, faker_fn, None)
        if fn_callable:
            return str(fn_callable())
    except Exception:
        pass

    # Last resort — generate something length-appropriate
    min_l = profile.get("min_len", 4)
    max_l = min(profile.get("max_len", 20), 40)
    return _faker.lexify("?" * _rnd.randint(min_l, max_l))


def _generate_one(kind: str, profile: dict, faker_fn: str):
    """Dispatch to the correct per-kind generator. Returns a raw Python value."""
    if kind == "int":          return _gen_int(profile)
    if kind == "float":        return _gen_float(profile)
    if kind == "bool":         return _gen_bool(profile)
    if kind == "datetime":     return _gen_datetime(profile)
    if kind == "date_str":     return _gen_date_str(profile)
    if kind == "numeric_str":  return _gen_numeric_str(profile)
    if kind == "pattern":      return _gen_pattern(profile)
    if kind == "enum":         return _gen_enum(profile)
    if kind == "text":         return _gen_text(profile)
    return _gen_string(profile, faker_fn)  # "string" — semantic Faker method


# ─── Column classification ────────────────────────────────────────────────────

# Which Faker methods belong to which entity factory
_PERSON_FNS  = {"first_name","last_name","name","prefix","suffix",
                "email","user_name","password","phone_number",
                "date_of_birth","ssn","job"}
_ADDRESS_FNS = {"address","street_address","secondary_address",
                "city","state_abbr","state","zipcode","postcode","country"}
_COMPANY_FNS = {"company","company_email"}

# Factory field lookup
_PERSON_FIELDS = {
    "first_name":"first_name","last_name":"last_name","name":"name",
    "prefix":"prefix","suffix":"suffix","email":"email",
    "user_name":"user_name","password":"password",
    "phone_number":"phone_number","date_of_birth":"date_of_birth",
    "ssn":"ssn","job":"job",
}
_ADDRESS_FIELDS = {
    "address":"address","street_address":"street_address",
    "secondary_address":"secondary_address","city":"city",
    "state_abbr":"state_abbr","state":"state",
    "zipcode":"zipcode","postcode":"postcode","country":"country",
}

# Methods Cortex handles better than rule-based generation
_CORTEX_FNS  = {"word","sentence","text","paragraph"}
# Methods always handled by rule-based generation (never use Cortex)
_CORTEX_SKIP = (
    _PERSON_FNS | _ADDRESS_FNS | _COMPANY_FNS |
    {"random_int","pyfloat","boolean","uuid4","credit_card_number",
     "iban","bban","ipv4","ipv6","url","zipcode","state_abbr",
     "latitude","longitude","currency_code","color_name","job",
     "__passthrough__"}
)


# ─── AI column-name → faker_fn mapper ────────────────────────────────────────
#
# This is the ONLY place AI/keywords map a column name to a faker_fn.
# The profile's "kind" always wins at generation time — so even if the mapper
# returns "address" for EFFECTIVE_DATE, _profile_column will have set
# kind="date_str" and the date generator fires, ignoring the faker_fn.

_COL_KEYWORD_RULES: list[tuple[list[str], str]] = [
    # Person
    (["first_name","fname","given_name"],        "first_name"),
    (["last_name","lname","surname","family"],    "last_name"),
    (["full_name","customer_name","holder_name",
      "insured_name","member_name","_name"],      "name"),
    (["email","e_mail","mail"],                   "email"),
    (["phone","mobile","cell","tel"],             "phone_number"),
    (["username","user_name","login"],            "user_name"),
    (["password","passwd","pwd"],                 "password"),
    (["ssn","sin","national_id","tax_id"],        "ssn"),
    (["dob","birth_date","date_of_birth"],        "date_of_birth"),
    (["job","title","occupation","position"],     "job"),
    # Address
    (["street","address_line","addr_line"],       "street_address"),
    (["address","addr"],                          "address"),
    (["city","town","municipality"],              "city"),
    (["state","province","region"],               "state_abbr"),
    (["zip","postal","postcode"],                 "zipcode"),
    (["country","nation"],                        "country"),
    # Company
    (["company","employer","organization","org"], "company"),
    # Dates — any column with date-like words maps to date_this_decade
    # (profile "kind" will override to date_str/datetime if samples confirm)
    (["_date","date_","effective","expir","start_dt","end_dt",
      "inception","issued","_dt","timestamp","created","updated",
      "modified","processed","received"],         "date_this_decade"),
    # Codes / IDs
    (["policy_num","pol_num","policy_no","pol_no",
      "policy_id","pol_id"],                      "bothify"),
    (["ref_num","ref_no","refnum","invoice_num",
      "invoice_no","claim_num","claim_no",
      "order_num","order_no","cert_num","cert_no",
      "batch_num","txn_id","transaction_id",
      "_code","_ref","_num","_no"],               "bothify"),
    (["_id","id_","identifier"],                  "random_int"),
    # Numeric
    (["amount","premium","price","cost","salary",
      "balance","payment","total","rate","fee"],  "pyfloat"),
    (["count","qty","quantity","num_"],            "random_int"),
    (["latitude","lat_"],                         "latitude"),
    (["longitude","lon_","lng_"],                 "longitude"),
    # Other
    (["uuid","guid"],                             "uuid4"),
    (["ip_address","ip_addr"],                    "ipv4"),
    (["url","website","link"],                    "url"),
    (["credit_card","cc_num"],                    "credit_card_number"),
    (["iban"],                                    "iban"),
    (["currency"],                                "currency_code"),
    (["color","colour"],                          "color_name"),
    (["description","notes","comment","remarks",
      "summary","detail","narrative"],            "sentence"),
    (["status","type","category","class",
      "gender","flag","indicator"],               "random_element"),
]

def _map_col_by_name(col: str) -> str | None:
    """Return a faker_fn based on column name keywords, or None if no match."""
    col_l = col.lower()
    for keywords, fn in _COL_KEYWORD_RULES:
        if any(kw in col_l for kw in keywords):
            return fn
    return None


def ai_map_faker_columns(
    columns: list[str],
    ai_engine: str,
    df_sample: pd.DataFrame = None,
    ollama_url=None, ollama_model=None, ollama_timeout=180,
    sf_conn=None, cortex_model=None,
) -> dict[str, str]:
    """Map each column to a faker_fn.

    Strategy:
      1. Try AI (Ollama or Cortex) with column name + sample values.
      2. For any column the AI maps poorly (returns an address method for
         a non-address column), fall back to keyword rules.
      3. Profile "kind" always wins at generation time — so even a bad
         mapping is harmless for date/numeric/pattern/enum columns.
    """
    # Build sample dict for the AI prompt
    col_samples: dict[str, list] = {}
    if df_sample is not None and not df_sample.empty:
        for col in columns:
            col_samples[col] = df_sample[col].dropna().astype(str).head(6).tolist()
    else:
        col_samples = {col: [] for col in columns}

    _ADDRESS_METHODS = {"address","street_address","secondary_address",
                        "city","state_abbr","state","zipcode","postcode","country"}
    _ADDR_COL_WORDS  = {"address","addr","street","city","state","zip",
                        "postal","country","location","loc"}

    ai_result: dict[str, str] = {}
    prompt = _build_mapping_prompt(col_samples)

    try:
        raw = ""
        if ai_engine == "Ollama (LLaMA)" and ollama_url and ollama_model:
            resp = requests.post(
                f"{ollama_url.rstrip('/')}/api/chat",
                json={
                    "model":    ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream":   False,
                    "options":  {"temperature": 0, "num_predict": 1024},
                },
                timeout=ollama_timeout,
            )
            resp.raise_for_status()
            raw = resp.json()["message"]["content"].strip()

        elif ai_engine == "Snowflake Cortex" and sf_conn and cortex_model:
            cur = sf_conn.cursor()
            escaped = prompt.replace("'", "\\'")
            cur.execute(f"SELECT SNOWFLAKE.CORTEX.COMPLETE('{cortex_model}', '{escaped}')")
            row = cur.fetchone()
            raw = (row[0] if row else "").strip()

        if raw:
            raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                ai_result = parsed
    except Exception:
        pass

    # Build final mapping: AI result + address-blacklist fix + keyword fallback
    final: dict[str, str] = {}
    for col in columns:
        fn = ai_result.get(col, "")

        # Validate AI returned a known Faker method
        if fn and fn not in {"__passthrough__"} and not hasattr(_faker, fn):
            fn = ""

        # Reject address methods for non-address columns
        if fn in _ADDRESS_METHODS:
            col_l = col.lower()
            if not any(kw in col_l for kw in _ADDR_COL_WORDS):
                fn = ""   # force keyword/passthrough fallback

        # Keyword rule fallback
        if not fn:
            fn = _map_col_by_name(col) or "__passthrough__"

        final[col] = fn

    return final


def _build_mapping_prompt(col_samples: dict) -> str:
    samples_str = json.dumps(col_samples, indent=2, default=str)
    return f"""You are a data generation assistant.
Given column names and sample values from a database table, assign the best Faker method for generating realistic fake data.

Available methods: name, first_name, last_name, email, phone_number, ssn, address, street_address, city, state_abbr, zipcode, country, company, user_name, password, ipv4, ipv6, url, date_of_birth, date_this_decade, date_time_this_decade, credit_card_number, iban, bban, sentence, uuid4, job, latitude, longitude, random_int, pyfloat, boolean, color_name, currency_code, bothify, word.

Rules (strictly follow these — they override your own judgment):
- Look at sample VALUES more than column names.
- Date-shaped values (e.g. "2025-01-04", "01/15/2024") → date_this_decade
- Timestamp values (e.g. "2025-01-04 10:30:00") → date_time_this_decade
- Coded IDs with letters+digits+separators (e.g. "POL-2025-100003") → bothify
- Pure numeric strings → random_int
- 2-letter codes that look like US states → state_abbr
- Columns with only a few distinct values (status, type, category) → word (not address, city, or state)
- Numeric columns for money/amounts → pyfloat
- NEVER assign address/city/state/zipcode/country to a column unless its name clearly contains "address", "city", "state", "zip", or "country".
- Return ONLY a JSON object. No markdown, no explanation.

Columns:
{samples_str}

Response (JSON only):"""


# ─── Cortex AI value generator ────────────────────────────────────────────────

def _cortex_generate_col(col_name: str, samples: list[str], n: int,
                          sf_conn, model: str) -> list[str] | None:
    """Generate n values for a column using Cortex AI in batches of 50."""
    if not sf_conn or not model or not samples:
        return None
    BATCH  = 50
    result = []
    samp_s = json.dumps(samples[:6])
    try:
        cur = sf_conn.cursor()
        while len(result) < n:
            b = min(BATCH, n - len(result))
            prompt = (
                f"Generate exactly {b} realistic fake values for a database "
                f"column called '{col_name}'. "
                f"Sample real values: {samp_s}. "
                f"Match format, vocabulary, and length of samples exactly. "
                f"Return ONLY a JSON array of {b} strings. No markdown."
            )
            cur.execute(
                f"SELECT SNOWFLAKE.CORTEX.COMPLETE('{model}', "
                f"'{prompt.replace(chr(39), chr(39)+chr(39))}') "
            )
            row = cur.fetchone()
            if not row:
                break
            raw = re.sub(r"^```(?:json)?|```$", "", row[0].strip(), flags=re.MULTILINE).strip()
            m   = re.search(r"\[.*?\]", raw, re.DOTALL)
            if not m:
                break
            batch = json.loads(m.group())
            if not isinstance(batch, list) or not batch:
                break
            result.extend(str(v) for v in batch)
        if not result:
            return None
        while len(result) < n:
            result.extend(result[: n - len(result)])
        return result[:n]
    except Exception:
        return None


# ─── Main generation function ─────────────────────────────────────────────────

def generate_fake_dataframe(
    columns:     list[str],
    faker_map:   dict[str, str],
    df_original: pd.DataFrame,
    n_rows:      int,
    sf_conn=None,
    cortex_model: str = None,
) -> pd.DataFrame:
    """Generate n_rows of demo data column by column.

    For each column the pipeline is:
      1. Profile the original data  → profile["kind"] drives everything.
      2. If kind is handled by profile (date/int/float/bool/enum/pattern/numeric_str)
         → use the appropriate fuzzy/Faker generator directly.
      3. If kind is "string" and faker_fn is a person/address/company field
         → pull from the corresponding factory_boy entity (entity-consistent).
      4. If kind is "string" and Cortex AI is available and faker_fn is in
         _CORTEX_FNS  → use Cortex for domain vocabulary.
      5. Otherwise → _gen_string(profile, faker_fn) via _SEMANTIC_MAP.

    Values are cast back to the original dtype after generation.
    """

    # ── Build profiles ────────────────────────────────────────────────────────
    profiles: dict[str, dict] = {}
    for col in columns:
        if (df_original is not None
                and col in df_original.columns
                and not df_original[col].dropna().empty):
            profiles[col] = _profile_column(df_original[col])
        else:
            profiles[col] = {"kind":"string","dtype_str":"object",
                             "nullable":False,"null_rate":0.0}

    # ── Detect which entity factories are needed ──────────────────────────────
    need_person  = any(faker_map.get(c,"") in _PERSON_FNS  for c in columns)
    need_address = any(faker_map.get(c,"") in _ADDRESS_FNS for c in columns)
    need_company = any(faker_map.get(c,"") in _COMPANY_FNS for c in columns)

    person_rows  = [_PersonFactory()  for _ in range(n_rows)] if need_person  else []
    address_rows = [_AddressFactory() for _ in range(n_rows)] if need_address else []
    company_rows = [_CompanyFactory() for _ in range(n_rows)] if need_company else []

    # ── Pre-generate Cortex columns ───────────────────────────────────────────
    cortex_data: dict[str, list] = {}
    if sf_conn and cortex_model:
        for col in columns:
            fn      = faker_map.get(col, "__passthrough__")
            profile = profiles[col]
            if profile["kind"] != "string":
                continue   # profile handles it — no Cortex needed
            if fn not in _CORTEX_FNS:
                continue
            if fn in _CORTEX_SKIP:
                continue
            samples = profile.get("sample_values", [])
            if not samples:
                continue
            generated = _cortex_generate_col(col, samples, n_rows, sf_conn, cortex_model)
            if generated:
                cortex_data[col] = generated

    # ── Generate each column ──────────────────────────────────────────────────
    data: dict[str, list] = {}

    for col in columns:
        fn      = faker_map.get(col, "__passthrough__")
        profile = profiles[col]
        kind    = profile["kind"]
        nullable  = profile.get("nullable", False)
        null_rate = profile.get("null_rate", 0.0)

        values: list = []
        for row_i in range(n_rows):
            # Nullable injection
            if nullable and null_rate > 0 and _rnd.random() < null_rate:
                values.append(None)
                continue

            # ── Cortex AI ────────────────────────────────────────────────────
            if col in cortex_data:
                values.append(cortex_data[col][row_i])
                continue

            # ── Profile-driven generators (kind always wins) ──────────────────
            if kind == "int":
                values.append(_gen_int(profile))
            elif kind == "float":
                values.append(_gen_float(profile))
            elif kind == "bool":
                values.append(_gen_bool(profile))
            elif kind == "datetime":
                values.append(_gen_datetime(profile))
            elif kind == "date_str":
                values.append(_gen_date_str(profile))
            elif kind == "numeric_str":
                values.append(_gen_numeric_str(profile))
            elif kind == "pattern":
                values.append(_gen_pattern(profile))
            elif kind == "enum":
                values.append(_gen_enum(profile))
            elif kind == "text":
                values.append(_gen_text(profile))

            # ── Entity factory (string kind, semantic fn) ────────────────────
            elif fn in _PERSON_FNS and person_rows:
                field = _PERSON_FIELDS.get(fn, "name")
                values.append(person_rows[row_i].get(field, person_rows[row_i]["name"]))

            elif fn in _ADDRESS_FNS and address_rows:
                field = _ADDRESS_FIELDS.get(fn, "address")
                values.append(address_rows[row_i].get(field, address_rows[row_i]["address"]))

            elif fn in _COMPANY_FNS and company_rows:
                field = "company" if fn == "company" else "company_email"
                values.append(company_rows[row_i].get(field, company_rows[row_i]["company"]))

            # ── Semantic Faker / passthrough ─────────────────────────────────
            else:
                values.append(_gen_string(profile, fn))

        # ── Cast to original dtype ────────────────────────────────────────────
        dtype_str = profile.get("dtype_str", "")
        try:
            if kind == "int" or "int" in dtype_str:
                if nullable:
                    values = pd.array(
                        [int(v) if v is not None else pd.NA for v in values],
                        dtype=pd.Int64Dtype(),
                    )
                else:
                    values = pd.array(
                        [int(v) if v is not None else 0 for v in values],
                        dtype=dtype_str if "int" in dtype_str else "int64",
                    )
            elif kind == "float" or "float" in dtype_str:
                dp     = profile.get("decimal_places", 2)
                values = [round(float(v), dp) if v is not None else None for v in values]
                values = pd.array(values, dtype=dtype_str if "float" in dtype_str else "float64")
            elif kind == "bool" or "bool" in dtype_str:
                values = [bool(v) if v is not None else None for v in values]
            elif kind == "datetime" or "datetime" in dtype_str:
                values = pd.to_datetime(values, errors="coerce")
                if not profile.get("time_varies", True):
                    values = values.normalize()
            elif kind in ("date_str", "numeric_str", "pattern"):
                values = [str(v) if v is not None else None for v in values]
        except Exception:
            # If cast fails, leave as list of Python objects — Pandas will infer
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

def _make_snowflake_conn(account, user, password, warehouse, database, schema, role):
    """Always creates a fresh Snowflake connection (never cached)."""
    return connect(
        account=account, user=user, password=password,
        warehouse=warehouse, database=database, schema=schema,
        role=role or None,
        login_timeout=30,
        network_timeout=60,
    )

def _sf_conn_alive(conn) -> bool:
    """Return True if the connection is still valid, False if expired/closed."""
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        return True
    except Exception:
        return False

def get_snowflake_conn(account, user, password, warehouse, database, schema, role):
    """Return a live Snowflake connection, refreshing if the token has expired."""
    conn = st.session_state.get("_sf_raw_conn")
    if conn is None or not _sf_conn_alive(conn):
        conn = _make_snowflake_conn(account, user, password, warehouse, database, schema, role)
        st.session_state["_sf_raw_conn"] = conn
    return conn

def _sf_execute(conn, sql, fetch="all"):
    """Execute SQL on a Snowflake connection; converts token-expiry errors to a clear message."""
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchall() if fetch == "all" else cur.fetch_pandas_all()
    except Exception as e:
        if "390114" in str(e) or "token" in str(e).lower() or "expired" in str(e).lower():
            raise RuntimeError(
                "🔑 Snowflake session expired. Please click Connect to refresh your session."
            ) from e
        raise

def snowflake_fetch_tables(conn, database, schema):
    rows = _sf_execute(conn, f"SHOW TABLES IN {database}.{schema}", fetch="all")
    return [r[1] for r in rows]

def snowflake_fetch_data(conn, database, schema, table, limit):
    return _sf_execute(
        conn,
        f'SELECT * FROM "{database}"."{schema}"."{table}" LIMIT {limit}',
        fetch="pandas"
    )

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
def get_sqlserver_engine(server, database, username, password, driver,
                          port=1433, conn_timeout=30, is_azure=False):
    """Build a SQLAlchemy engine for SQL Server / Azure SQL.

    Azure SQL requires Encrypt=yes and does not support Windows auth.
    Special characters in passwords are percent-encoded to avoid parse errors.
    """
    driver_enc = driver.replace(" ", "+")
    # Base ODBC params
    odbc_params = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server},{port};"
        f"DATABASE={database};"
        f"Connection Timeout={conn_timeout};"
    )
    if is_azure or any(x in server.lower() for x in
                       ("database.windows.net", "database.azure.com", ".database.")):
        # Azure SQL — always encrypted, no Windows auth
        odbc_params += "Encrypt=yes;TrustServerCertificate=no;"
        if username and password:
            odbc_params += f"UID={username};PWD={password};"
        conn_str = f"mssql+pyodbc:///?odbc_connect={quote_plus(odbc_params)}"
    elif username and password:
        # On-premise with SQL auth — encode password to handle special chars
        odbc_params += f"UID={username};PWD={password};Encrypt=no;"
        conn_str = f"mssql+pyodbc:///?odbc_connect={quote_plus(odbc_params)}"
    else:
        # On-premise Windows auth
        odbc_params += "Trusted_Connection=yes;"
        conn_str = f"mssql+pyodbc:///?odbc_connect={quote_plus(odbc_params)}"

    return create_engine(conn_str, connect_args={"timeout": conn_timeout})

def sqlserver_fetch_tables(engine):
    return inspect(engine).get_table_names()

def sqlserver_fetch_data(engine, table, limit):
    return pd.read_sql(f"SELECT TOP {limit} * FROM [{table}]", engine)

def sqlserver_create_clone_db(engine, tgt_db: str, table_masked_map: dict,
                               sql_params: dict = None):
    """Create a new SQL Server database and write masked tables into it.

    CREATE DATABASE must run outside any transaction (autocommit=True).
    We use a raw pyodbc connection for that step, then a fresh SQLAlchemy
    engine for the actual table writes.
    """
    results = {}

    # Step 1: Create the target DB using a raw pyodbc autocommit connection
    # so that CREATE DATABASE never runs inside a transaction.
    try:
        p = sql_params or {}
        driver       = p.get("driver", "ODBC Driver 17 for SQL Server")
        server       = p.get("server", "")
        port         = p.get("port", 1433)
        username     = p.get("username", "")
        password     = p.get("password", "")
        is_azure     = p.get("is_azure", False)
        conn_timeout = p.get("conn_timeout", 30)

        odbc_str = (
            f"DRIVER={{{driver}}};"
            f"SERVER={server},{port};"
            f"DATABASE=master;"          # connect to master to create a new DB
            f"Connection Timeout={conn_timeout};"
        )
        if is_azure or "database.windows.net" in server.lower():
            odbc_str += "Encrypt=yes;TrustServerCertificate=no;"
        if username and password:
            odbc_str += f"UID={username};PWD={password};"
        else:
            odbc_str += "Trusted_Connection=yes;"

        raw_conn = pyodbc.connect(odbc_str, autocommit=True)
        cur = raw_conn.cursor()
        cur.execute(f"IF DB_ID(N'{tgt_db}') IS NULL CREATE DATABASE [{tgt_db}]")
        raw_conn.close()
    except Exception as e:
        return {t: f"❌ Could not create DB [{tgt_db}]: {e}" for t in table_masked_map}

    # Step 2: Build a fresh SQLAlchemy engine pointing at the new target DB
    try:
        if sql_params:
            tgt_engine = get_sqlserver_engine(
                server       = sql_params["server"],
                database     = tgt_db,
                username     = sql_params.get("username", ""),
                password     = sql_params.get("password", ""),
                driver       = sql_params.get("driver", "ODBC Driver 17 for SQL Server"),
                port         = sql_params.get("port", 1433),
                conn_timeout = sql_params.get("conn_timeout", 30),
                is_azure     = sql_params.get("is_azure", False),
            )
        else:
            tgt_engine = engine
    except Exception as e:
        return {t: f"❌ Could not connect to target DB [{tgt_db}]: {e}" for t in table_masked_map}

    # Step 3: Write each table
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
        sql_server   = st.text_input("Server", placeholder="myserver.database.windows.net")
        sql_database = st.text_input("Database")
        sql_username = st.text_input("Username", placeholder="user or user@server")
        sql_password = st.text_input("Password", type="password")
        available_drivers = [d for d in pyodbc.drivers() if "SQL Server" in d] or ["ODBC Driver 17 for SQL Server"]
        sql_driver   = st.selectbox("ODBC Driver", available_drivers)
        _is_azure_default = any(x in sql_server.lower() for x in
                                ("database.windows.net", "database.azure.com", ".database."))
        sql_c1, sql_c2 = st.columns(2)
        with sql_c1:
            sql_port    = st.number_input("Port", value=1433, min_value=1, max_value=65535)
        with sql_c2:
            sql_timeout = st.number_input("Timeout (s)", value=30, min_value=5, max_value=120)
        sql_is_azure = st.toggle("Azure SQL / Azure Managed Instance",
                                  value=_is_azure_default,
                                  help="Enables Encrypt=yes and TrustServerCertificate=no required by Azure SQL.")
        if sql_is_azure:
            st.info("🔒 Azure SQL mode: encrypted connection enabled automatically.")

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

    # Safe defaults — ensure sql_* vars are always defined regardless of source_type
    if source_type != "SQL Server":
        sql_server = sql_database = sql_username = sql_password = sql_driver = ""
        sql_port = 1433
        sql_timeout = 30
        sql_is_azure = False

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
    "active_output": None,    # "masked" or "demo" — drives Step 4
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
            # Clear any cached stale connection before attempting
            st.session_state.pop("_sf_raw_conn", None)
            try:
                conn = get_snowflake_conn(sf_account, sf_user, sf_password,
                                          sf_warehouse, sf_database, sf_schema, sf_role)
                st.session_state.connection = ("snowflake", conn, sf_database, sf_schema)
                st.session_state.tables     = snowflake_fetch_tables(conn, sf_database, sf_schema)
                st.success(f"Connected! Found {len(st.session_state.tables)} tables.")
            except Exception as e:
                err_str = str(e)
                if "390114" in err_str or "token" in err_str.lower() or "expired" in err_str.lower():
                    st.error(
                        "🔑 Snowflake authentication token expired. "
                        "Please click **Connect** again to start a fresh session."
                    )
                else:
                    st.error(f"Snowflake connection failed: {e}")

    elif source_type == "SQL Server":
        with st.spinner("Connecting to SQL Server..."):
            try:
                engine = get_sqlserver_engine(
                    sql_server, sql_database, sql_username, sql_password, sql_driver,
                    port=int(sql_port), conn_timeout=int(sql_timeout), is_azure=sql_is_azure,
                )
                with engine.connect(): pass
                st.session_state.connection = ("sqlserver", engine, sql_database, {
                    "server": sql_server, "username": sql_username,
                    "password": sql_password, "driver": sql_driver,
                    "port": int(sql_port), "conn_timeout": int(sql_timeout),
                    "is_azure": sql_is_azure,
                })
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
            f"🎭 Fetch & Generate Demo Data — {len(st.session_state.selected_tables)} table(s)",
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
                        _, engine, *_ = st.session_state.connection
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

    # ── Fetch & Generate Demo Data ─────────────────────────────────────────────
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
                    _, engine2, *_ = st.session_state.connection
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

        fake_bar.progress(1.0, text="Demo data column mapping complete!")
        st.session_state.faker_mapped     = True
        st.session_state.active_output    = "demo"
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
            expanded=False,
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

# ─── Step 3b: Demo Data Review & Generate ──────────────────────────────────────

if st.session_state.faker_mapped and st.session_state.faker_maps:
    st.divider()
    st.header("Step 3 — Review & Generate Demo Data")
    st.markdown(
        "AI has mapped each column to a provider method (for demo data generation). "
        "**Edit mappings** and set **row counts per table**, then click Generate."
    )

    # ── Global mode ──────────────────────────────────────────────────────────
    g1, g2 = st.columns([3, 2])
    with g1:
        fake_mode = st.radio(
            "Generation mode",
            ["Replace all data with demo data", "Append demo rows to existing data"],
            key="fake_mode_radio",
            horizontal=True,
            help="Replace: discard originals entirely. Append: add demo rows below original data.",
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
            expanded=False,
        ):
            # Per-table row count control
            rc_col, _ = st.columns([2, 4])
            with rc_col:
                tbl_rows = st.number_input(
                    "Demo rows to generate",
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
    if st.button("✨ Generate Demo Data for All Tables", type="primary", key="faker_gen_btn"):
        st.session_state.faker_dfs = {}
        gen_prog = st.progress(0, text="Generating...")
        tables_list = st.session_state.selected_tables

        # Resolve Cortex connection for generation (reuse data source conn if Snowflake)
        _gen_sf_conn    = None
        _gen_cortex_mdl = None
        if ai_engine == "Snowflake Cortex":
            _gen_cortex_mdl = cortex_model
            if st.session_state.connection and st.session_state.connection[0] == "snowflake":
                _gen_sf_conn = st.session_state.connection[1]
            elif st.session_state.get("cortex_conn"):
                _gen_sf_conn = st.session_state["cortex_conn"]

        for i, table in enumerate(tables_list):
            gen_prog.progress(i / len(tables_list), text=f"Generating `{table}`...")
            df_t   = st.session_state.table_dfs.get(table, pd.DataFrame())
            fmap   = st.session_state.faker_maps.get(table, {})
            n_rows = st.session_state.fake_row_overrides.get(table, len(df_t))
            if not fmap:
                continue
            fake_df = generate_fake_dataframe(
                list(df_t.columns), fmap, df_t, int(n_rows),
                sf_conn=_gen_sf_conn, cortex_model=_gen_cortex_mdl,
            )
            if fake_mode == "Append demo rows to existing data" and not df_t.empty:
                result_df = pd.concat([df_t, fake_df], ignore_index=True)
            else:
                result_df = fake_df
            st.session_state.faker_dfs[table] = result_df
        gen_prog.progress(1.0, text="Demo data generation complete!")
        st.session_state.active_output = "demo"
        st.rerun()

    # Preview
    if st.session_state.faker_dfs:
        st.subheader("Preview Generated Demo Data")
        for table, fdf in st.session_state.faker_dfs.items():
            with st.expander(f"📋 **{table}** — {len(fdf):,} rows", expanded=False):
                st.dataframe(fdf.head(20), use_container_width=True)

# ─── Step 4: Export (masked OR demo, whichever was last generated) ─────────────

_has_output = bool(st.session_state.table_masked_dfs or st.session_state.faker_dfs)
_output_type = st.session_state.get("active_output")  # "masked" or "demo"

if _has_output and _output_type:
    st.divider()
    _label = "Masked Data" if _output_type == "masked" else "Demo Data"
    _export_dfs = st.session_state.table_masked_dfs if _output_type == "masked" else st.session_state.faker_dfs  # faker_dfs holds demo data
    _file_prefix = "masked" if _output_type == "masked" else "demo"
    _zip_name    = "masked_tables.zip" if _output_type == "masked" else "demo_tables.zip"

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
            _default_suffix = "_MASKED" if _output_type == "masked" else "_DEMO"
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
                _, engine_w, src_db, sql_conn_params = st.session_state.connection
                tgt_db = st.text_input("Target Database", value=f"{src_db}{_default_suffix}", key="tgt_db4_sql")
                if st.button(f"🚀 Write {_label} to SQL Server", type="primary", key="write4_sql"):
                    with st.spinner("Writing to SQL Server..."):
                        results = sqlserver_create_clone_db(
                            engine_w, tgt_db, _export_dfs,
                            sql_params=sql_conn_params,
                        )
                    for tbl, msg in results.items():
                        st.write(f"**{tbl}**: {msg}")

elif st.session_state.connection is None:
    st.info("👈 Select a data source in the sidebar and click Connect to begin.")

# ─── Setup instructions (commented out — uncomment for dev reference) ──────────

# with st.expander("ℹ️ Setup & prerequisites"):
#     st.markdown("""
# **Install packages:**
# ```bash
# pip install streamlit pandas snowflake-connector-python requests pyodbc sqlalchemy faker
# ```
#
# **Ollama setup:**
# ```bash
# ollama pull llama3
# ollama serve   # runs on http://localhost:11434
# ```
#
# **Masking rules:**
#
# | Value length | Example | Masked |
# |---|---|---|
# | ≤ 4 chars | `John` | `****` |
# | 5–10 chars | `john@x.co` | `j*******o` |
# | > 10 chars | `john@email.com` | `jo**********om` |
# """)
