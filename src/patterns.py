import re
from dataclasses import dataclass
from typing import Pattern, List


@dataclass(frozen=True)
class FindingRule:
    name: str
    severity: int  # 1..5
    pattern: Pattern
    description: str


def build_rules() -> List[FindingRule]:
    # NOTE: Heuristic patterns. We never store secrets; we only flag risk.
    rules = [
        FindingRule(
            name="seed_phrase_like_12_24_words",
            severity=5,
            pattern=re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b", re.IGNORECASE),
            description="Looks like a 12–24 word mnemonic/seed phrase. Treat as catastrophic exposure."
        ),
        FindingRule(
            name="private_key_pem",
            severity=5,
            pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            description="Private key block detected (PEM/OpenSSH)."
        ),
        FindingRule(
            name="jwt_token",
            severity=4,
            pattern=re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
            description="JWT-like token detected."
        ),
        FindingRule(
            name="aws_access_key_id",
            severity=4,
            pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            description="AWS Access Key ID pattern detected."
        ),
        FindingRule(
            name="generic_api_key",
            severity=3,
            pattern=re.compile(r"\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.IGNORECASE),
            description="Potential API key/secret/token assignment detected."
        ),
        FindingRule(
            name="password_assignment",
            severity=3,
            pattern=re.compile(r"\b(password|pass)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE),
            description="Password-like assignment detected."
        ),
        FindingRule(
            name="crypto_address",
            severity=2,
            pattern=re.compile(r"\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
            description="Potential crypto address detected."
        ),
        FindingRule(
            name="pii_email",
            severity=2,
            pattern=re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
            description="Email address detected (PII)."
        ),
    ]
    return rules
