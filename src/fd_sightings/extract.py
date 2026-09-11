from __future__ import annotations

import re

from .models import Extraction, Message


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.IGNORECASE)
GCVE_RE = re.compile(r"\bGCVE-\d+-\d{4}-\d{4,}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS:[34]\.\d/[A-Z]+:[A-Z](?:/[A-Z]+:[A-Z]+)+", re.IGNORECASE)

VULN_TERMS = re.compile(
    r"\b(vulnerabilit(?:y|ies)|CVE-|exploit|remote code execution|RCE|buffer overflow|"
    r"use-after-free|path traversal|directory traversal|injection|cross-site scripting|XSS|SSRF|"
    r"privilege escalation|authentication bypass|arbitrary file|denial of service|DoS)\b",
    re.IGNORECASE,
)

VERSION_TOKEN = re.compile(r"^(?:v?\d+(?:\.\d+)+(?:[-._a-z0-9]*)?|through$|before$|after$|<=|>=)$", re.IGNORECASE)
PREFIX = re.compile(r"^(?:re:\s*|fwd?:\s*|\[[^]]+\]\s*)+", re.IGNORECASE)
IDENTIFIER_ONLY_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GCVE-\d+-\d{4}-\d{4,}|"
    r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})$",
    re.IGNORECASE,
)
ADVISORY_PREFIX_RE = re.compile(
    r"^(?:(?:[A-Z][A-Z0-9._]*)-SA-\d{1,4}(?:-\d{1,4}){2,4}|"
    r"(?:[A-Z][\w.&-]*(?:\s+[A-Z][\w.&-]*){0,3})\s+SA-\d{6,8}(?:-\d+)*)"
    r"\s*(?::|-)?\s+",
    re.IGNORECASE,
)
VERSION_CONTEXT_RE = re.compile(
    r"\b(?:versions?|v)\s*(?:before|through|up to|<=|<|affected:?)?\s*"
    r"(v?\d+(?:\.\d+){1,3}(?:[-._a-z0-9]+)?)",
    re.IGNORECASE,
)
VERSION_CONSTRAINT_RE = re.compile(
    r"\b(?:versions?|v)?\s*(before|prior to|through|up to|<=|<|>=|>|after)\s*"
    r"(v?\d+(?:\.\d+){1,3}(?:[-._a-z0-9]+)?)", re.IGNORECASE,
)
FIXED_VERSION_RE = re.compile(
    r"\b(?:fixed|patched|resolved)\s+(?:in|by|with)?\s*(?:version|release|v)?\s*"
    r"(v?\d+(?:\.\d+){1,3}(?:[-._a-z0-9]+)?)", re.IGNORECASE,
)
COMMIT_RE = re.compile(r"\b(?:commit|revision)\s+([0-9a-f]{7,40})\b", re.IGNORECASE)
POC_LINK_RE = re.compile(
    r"(?:(?:^|[/_.-])(?:poc|proof[-_ ]of[-_ ]concept|exploit)(?:$|[/_.-])|"
    r"(?:github|gitlab)\.com/[^\s/]+/[^\s/]*(?:poc|exploit)|exploit-db\.com/exploits/)",
    re.IGNORECASE,
)
EMBEDDED_POC_RE = re.compile(
    r"(?m)^(?:\s{0,4}(?:\$|#)\s+)?(?:curl|wget)\s+(?:-[A-Za-z]+\s+)*https?://\S+|"
    r"^#!\s*/usr/bin/(?:env\s+)?(?:python\d*|bash|sh|perl|ruby)\b",
    re.IGNORECASE,
)
FIELD_RE = re.compile(r"(?im)^\s*(vendor|product|component|module|aliases?)\s*:\s*([^\r\n]+)")
VULNERABILITY_TYPES = {
    "buffer-overflow": re.compile(r"\bbuffer overflow\b", re.IGNORECASE),
    "code-execution": re.compile(r"\b(?:remote |arbitrary )?code execution|\bRCE\b", re.IGNORECASE),
    "cross-site-scripting": re.compile(r"\bcross-site scripting\b|\bXSS\b", re.IGNORECASE),
    "denial-of-service": re.compile(r"\bdenial of service\b|\bDoS\b", re.IGNORECASE),
    "path-traversal": re.compile(r"\b(?:path|directory) traversal\b", re.IGNORECASE),
    "privilege-escalation": re.compile(r"\bprivilege escalation\b", re.IGNORECASE),
    "sql-injection": re.compile(r"\bSQL injection\b|\bSQLi\b", re.IGNORECASE),
    "ssrf": re.compile(r"\bSSRF\b|server-side request forgery", re.IGNORECASE),
    "use-after-free": re.compile(r"\buse-after-free\b", re.IGNORECASE),
}


def _unique(pattern: re.Pattern[str], text: str) -> list[str]:
    return sorted({match.upper() for match in pattern.findall(text)})


def product_hint(title: str) -> str:
    cleaned = PREFIX.sub("", title).strip()
    cleaned = ADVISORY_PREFIX_RE.sub("", cleaned).strip()
    tokens = cleaned.split()
    if tokens and IDENTIFIER_ONLY_RE.match(tokens[0].strip("()[],:;")):
        # An identifier-only title prefix says nothing about the product.  A
        # resolved explicit record can provide an unambiguous affected product
        # later; treating the identifier as a product creates records such as
        # vendor=CVE, product=CVE-2026-....
        return ""
    selected: list[str] = []
    stopwords = {"authenticated", "unauthenticated", "remote", "local", "multiple", "stored"}
    for token in tokens[:8]:
        bare = token.strip("()[],:;")
        if selected and (not bare or bare in {"-", "–", "—", "|"}):
            break
        if VERSION_TOKEN.match(bare) or bare.lower() in stopwords:
            break
        if bare.upper() in {"RCE", "XSS", "SSRF", "SQLI", "LPE"}:
            break
        selected.append(bare)
        if len(selected) == 3:
            break
    return " ".join(selected).strip()


def extract(message: Message) -> Extraction:
    text = f"{message.title}\n{message.body}"
    evidence: list[str] = []
    score = 0
    fields: dict[str, list[str]] = {}
    for name, value in FIELD_RE.findall(text):
        fields.setdefault(name.casefold(), []).append(value.strip()[:200])
    explicit_product = (fields.get("product") or [""])[0]
    explicit_product = ADVISORY_PREFIX_RE.sub("", explicit_product).strip()
    if IDENTIFIER_ONLY_RE.match(explicit_product):
        explicit_product = ""
    aliases = fields.get("alias", []) + fields.get("aliases", [])
    constraints = [
        {"operator": match.group(1).casefold(), "version": match.group(2)}
        for match in VERSION_CONSTRAINT_RE.finditer(text)
    ]
    fixed_versions = {match.group(1) for match in FIXED_VERSION_RE.finditer(text)}
    affected_versions = {
        match.group(1) for match in VERSION_CONTEXT_RE.finditer(text)
    } - fixed_versions
    poc_links = sorted({link for link in message.links if POC_LINK_RE.search(link)})

    if re.search(r"\b(proof[- ]of[- ]concept|PoC)\b", text, re.IGNORECASE):
        evidence.append("explicit PoC wording")
        # BCP-12 defines publication of a PoC as its own sighting type.  An
        # explicit label is sufficient evidence; the additional indicators
        # below remain useful for less clearly labelled reports.
        score += 3
    if re.search(r"(?:^|\n)(?:GET|POST|PUT|PATCH|DELETE)\s+/\S+\s+HTTP/", text):
        evidence.append("embedded HTTP request")
        score += 3
    if EMBEDDED_POC_RE.search(message.body):
        evidence.append("embedded executable example")
        score += 3
    if re.search(r"\b(payload|exploit code|reproduction steps|steps to reproduce)\b", text, re.IGNORECASE):
        evidence.append("payload or reproduction steps")
        score += 1
    if poc_links:
        evidence.append("public exploit repository")
        score += 1
    if re.search(r"(?:marker_exists=yes|arbitrary code execution|code execution (?:was|is) confirmed)", text, re.IGNORECASE):
        evidence.append("execution evidence")
        score += 1

    return Extraction(
        cve_ids=_unique(CVE_RE, text),
        ghsa_ids=_unique(GHSA_RE, text),
        gcve_ids=_unique(GCVE_RE, text),
        cwe_ids=_unique(CWE_RE, text),
        cvss_vectors=sorted(set(CVSS_RE.findall(text))),
        product_hint=explicit_product or product_hint(message.title),
        vendor_hint=(fields.get("vendor") or [""])[0],
        component_hint=(fields.get("component") or fields.get("module") or [""])[0],
        product_aliases=sorted({item.strip() for value in aliases for item in re.split(r"[,;]", value) if item.strip()}),
        affected_versions=sorted(affected_versions),
        version_constraints=constraints,
        fixed_versions=sorted(fixed_versions),
        commits=sorted({match.group(1).lower() for match in COMMIT_RE.finditer(text)}),
        vulnerability_types=sorted(name for name, pattern in VULNERABILITY_TYPES.items() if pattern.search(text)),
        poc_score=score,
        poc_evidence=evidence,
        poc_links=poc_links,
        relevant=bool(VULN_TERMS.search(text)),
    )
