from dataclasses import dataclass
from typing import List, Dict, Any
from .patterns import build_rules


@dataclass
class Finding:
    name: str
    severity: int
    description: str
    matches_count: int


def _score(findings: List[Finding]) -> int:
    """
    Risk score 0..100.
    Catastrophic items (severity 5) should push score high immediately.
    """
    if not findings:
        return 0

    base = 0
    for f in findings:
        # severity 1..5; count increases confidence
        base += (f.severity * 12) + min(10, f.matches_count * 2)

    return min(100, base)


def _recommendations(findings: List[Finding]) -> List[str]:
    recs = []
    if not findings:
        return ["No obvious secret leakage detected. Still avoid pasting credentials into AI tools."]

    names = {f.name for f in findings}

    if "seed_phrase_like_12_24_words" in names or "private_key_pem" in names:
        recs.append("Do not paste seed phrases or private keys into any AI/chat tool. Rotate/replace immediately if exposure is possible.")
        recs.append("Use a secure, offline recovery process and consider splitting control (threshold/social recovery).")

    if "jwt_token" in names or "aws_access_key_id" in names or "generic_api_key" in names:
        recs.append("Treat exposed tokens/keys as compromised. Revoke and reissue; audit access logs.")
        recs.append("Replace raw secrets with placeholders before sharing prompts (e.g., <API_KEY>, <TOKEN>).")

    if "password_assignment" in names:
        recs.append("Never paste passwords. Use redacted examples (e.g., password='<REDACTED>').")

    if "pii_email" in names:
        recs.append("Remove personal identifiers. Use synthetic examples (e.g., user@example.com).")

    recs.append("Adopt a prompt hygiene policy: no secrets, no live customer data, no production identifiers.")
    return recs


def audit_prompt(text: str) -> Dict[str, Any]:
    rules = build_rules()
    findings: List[Finding] = []

    for r in rules:
        matches = list(r.pattern.finditer(text))
        if matches:
            findings.append(
                Finding(
                    name=r.name,
                    severity=r.severity,
                    description=r.description,
                    matches_count=len(matches),
                )
            )

    score = _score(findings)
    recs = _recommendations(findings)

    # We deliberately avoid returning raw matched substrings.
    return {
        "risk_score": score,
        "findings": [f.__dict__ for f in sorted(findings, key=lambda x: (-x.severity, -x.matches_count))],
        "recommendations": recs,
    }
