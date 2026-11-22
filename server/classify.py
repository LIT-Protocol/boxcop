"""Narrow deterministic patterns, not comprehensive DLP or intent detection."""
import re
from urllib.parse import unquote, urlsplit, urlunsplit

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)", re.I)
SECRET_TOKEN = re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{12,})\b")
SECRET_ASSIGNMENT = re.compile(r"\b(?:aws_secret_access_key|aws_session_token|api[_ -]?key|access[_ -]?token|auth[_ -]?token|token|secret|password|passwd|authorization)[\"']?\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|(?:Bearer\s+)?[^\s;,]+)", re.I)
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+1[ -]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")
MEDICAL = re.compile(
    r"\b(?:patient\s+(?:record|name|id|diagnosis)|medical\s+(?:record|history|condition)|"
    r"diagnosed\s+with|prescribed\s+(?:insulin|medication))\b|"
    r"\bMRN\s*[:#=]?\s*\d{3,}\b", re.I,
)
# A lone "diagnosis:" is common incident language; clinical records combine markers.
CLINICAL_MARKERS = tuple(re.compile(pattern, re.I) for pattern in (
    r"\b(?:DOB|date\s+of\s+birth)\b", r"\bDx\b", r"\bRx\b", r"\bMRN\b", r"\bICD-?10\b",
    r"\bdiagnosis\s*[:=]", r"\b(?:prescription|medication)s?\b", r"\bsymptoms?\b",
))
PATIENT_CONTEXT = re.compile(r"\b(?:diagnosis|DOB|date\s+of\s+birth|MRN|prescription|medication|ICD-?10|symptom)\b", re.I)
HR = re.compile(
    r"\b(?:employee\s+(?:salary|ssn|compensation)|performance\s+(?:review|improvement\s+plan)|"
    r"personnel\s+(?:file|record)|confidential\s+(?:employee|payroll)|"
    r"disciplinary\s+action|termination\s+letter|harassment\s+complaint)\b", re.I,
)
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
# Require an authentication label adjacent to an actual code, not general advice
# or a bare number. These bounded English patterns are not semantic detection.
OTP_LABEL = r"(?:one[- ]time(?:[A-Za-z -]{0,48})|sign[- ]?in |login |authentication |verification |security |MFA |2FA )code"
OTP = re.compile(r"\b(?:" + OTP_LABEL + r")\s*(?:is\s*|[:=]\s*)?\d{6,8}\b|\b\d{6,8}\s+is\s+your\s+(?:" + OTP_LABEL + r")\b", re.I)
BUSINESS_RESTRICTION = re.compile(r"\b(?:confidential|board[- ]only|nonpublic|unannounced|embargoed|unreleased)\b", re.I)
BUSINESS_DETAIL = re.compile(r"\b(?:acquisition|merger|takeover|offer|earnings|revenue forecast|financial results)\b", re.I)
BUSINESS_VALUE = re.compile(r'\$\s*\d|\b\d+(?:\.\d+)?\s*(?:million|billion|percent)\b', re.I)


def restricted_business(text):
    # Scope both markers to a short sentence. Public news without a restriction
    # marker is not enough; generic confidentiality boilerplate is not enough.
    return any(BUSINESS_RESTRICTION.search(sentence) and BUSINESS_DETAIL.search(sentence) and BUSINESS_VALUE.search(sentence)
               for sentence in re.split(r'[.!?\n]', text) if len(sentence) <= 500)

URL = re.compile(
    r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|//)[^\s<>\"']+|"
    r"[^\s/:<>\"']+:[^\s/<>\"']+@[^\s<>\"']+|"
    r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[/?#][^\s<>\"']*", re.I,
)
PATH_TOKEN = re.compile(r"^(?:[A-Za-z0-9_-]{32,}|(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{16,})$")
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def classify(text: str) -> list[str]:
    labels = []
    if PRIVATE_KEY.search(text):
        labels.extend(("secret", "private-key"))
    elif SECRET_TOKEN.search(text) or any(literal_assignment(m) for m in SECRET_ASSIGNMENT.finditer(text)) or OTP.search(text):
        labels.append("secret")
    if restricted_business(text):
        labels.append('restricted-business')
    if SSN.search(text) or EMAIL.search(text) or PHONE.search(text):
        labels.append("pii")
    if SSN.search(text):
        labels.append("ssn")
    if MEDICAL.search(text) or (re.search(r"\bpatient\b", text, re.I) and PATIENT_CONTEXT.search(text)) \
            or sum(bool(marker.search(text)) for marker in CLINICAL_MARKERS) >= 2:
        labels.append("medical")
    if HR.search(text) or re.search(r"\bemployee\s+[^.!?\n]{1,100}\b(?:salary|compensation)\s*(?:of\s+|is\s+|[:=]\s*)?\$\s*\d", text, re.I):
        labels.append("hr-sensitive")
    return labels


# A quoted HTTP header can contain a reference that the shell expands later.
# Match the entire reference, so a literal bearer value still classifies.
BEARER_REFERENCE = re.compile(r"""Authorization:\s*Bearer\s+\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})(["'])""", re.I)
JS_TYPE_CHECK = re.compile(r"[\w-]+[ \t]*=[ \t]*typeof[ \t]+[A-Za-z_$][\w$]*[ \t]*={2,3}")


def literal_assignment(match) -> bool:
    text = match.string
    if re.fullmatch(r"[\w-]+[ \t]*={2,3}", match[0]):
        return False
    if JS_TYPE_CHECK.match(text, match.start()):
        return False
    header = BEARER_REFERENCE.fullmatch(match[0])
    if header and match.start() and text[match.start() - 1] == header[1]:
        return False
    return not redacted_assignment(match)


def redacted_assignment(match) -> bool:
    # Exempt only an entire, explicit placeholder value. Never exempt a document
    # merely because it mentions redaction; other matches still classify normally.
    value = re.split(r"[:=]", match[0], maxsplit=1)[1].strip().strip('"\'')
    value = re.sub(r"^Bearer\s+", "", value, flags=re.I).rstrip('.')
    return value.lower() in {'[redacted]', '<redacted>', '[removed]'}


def redact(text: str) -> str:
    result = PRIVATE_KEY.sub("[private key redacted]", text)
    result = OTP.sub('[authentication code redacted]', result)
    result = SECRET_ASSIGNMENT.sub("[credential redacted]", result)
    result = SECRET_TOKEN.sub("[credential redacted]", result)
    result = SSN.sub("[SSN redacted]", result)
    result = EMAIL.sub("[email redacted]", result)
    return PHONE.sub("[phone redacted]", result)


def _safe_url(match: re.Match) -> str:
    raw = match.group(0)
    scheme_match = SCHEME.match(raw)
    prefix = scheme_match[0] if scheme_match else ""
    body = raw[len(prefix):] if prefix else raw.removeprefix("//")
    # Remove through the last @ BEFORE parsing. Invalid unescaped ?/# in a
    # password must not turn it into a fragment retained as apparent hostname.
    authority, slash, path = body.partition("/")
    authority = authority.rsplit("@", 1)[-1]
    try:
        parsed = urlsplit((prefix or "//") + authority + slash + path)
        host = parsed.hostname
        if not host:
            return "[URL omitted]"
        if ":" in host:
            host = "[" + host + "]"
        if parsed.port is not None:
            host += ":" + str(parsed.port)
        safe_path = "/".join(
            "[path-redacted]" if PATH_TOKEN.fullmatch(unquote(unquote(segment))) else segment
            for segment in parsed.path.split("/")
        )
        return urlunsplit((parsed.scheme, host, safe_path, "", "")) if prefix else host + safe_path
    except ValueError:
        return "[URL omitted]"


def sanitize_metadata(text: str, *, truncate: bool = True) -> str:
    # Strip URL credentials before other patterns can turn a URL into fragments.
    result = URL.sub(_safe_url, text)
    result = redact(result)
    result = CONTROL.sub(" ", result)
    # Whole-body comparison must see the complete input before the storage cap.
    # Only that in-memory caller opts out; persisted metadata keeps the default.
    return result[:1024] if truncate else result
