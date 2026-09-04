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


def _unique(pattern: re.Pattern[str], text: str) -> list[str]:
    return sorted({match.upper() for match in pattern.findall(text)})


def product_hint(title: str) -> str:
    cleaned = PREFIX.sub("", title).strip()
    tokens = cleaned.split()
    selected: list[str] = []
    stopwords = {"authenticated", "unauthenticated", "remote", "local", "multiple", "stored"}
    for token in tokens[:8]:
        bare = token.strip("()[],:;")
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

    if re.search(r"\b(proof[- ]of[- ]concept|PoC)\b", text, re.IGNORECASE):
        evidence.append("explicit PoC wording")
        score += 2
    if re.search(r"(?:^|\n)(?:GET|POST|PUT|PATCH|DELETE)\s+/\S+\s+HTTP/", text):
        evidence.append("HTTP request")
        score += 2
    if re.search(r"\b(payload|exploit code|reproduction steps|steps to reproduce)\b", text, re.IGNORECASE):
        evidence.append("payload or reproduction steps")
        score += 1
    if re.search(r"github\.com/[^\s]+/(?:exploit|poc|0day)", text, re.IGNORECASE):
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
        product_hint=product_hint(message.title),
        poc_score=score,
        poc_evidence=evidence,
        relevant=bool(VULN_TERMS.search(text)),
    )
