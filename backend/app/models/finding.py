from dataclasses import dataclass


@dataclass
class Finding:
    rule_code: str
    severity: int
    explanation: str
