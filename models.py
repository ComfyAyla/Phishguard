from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass(frozen=True)
class EmailMessage:
    sender: str
    subject: str
    body: str
    links: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)  # <-- Added this field!
    raw: str = ""

@dataclass(frozen=True)
class Indicator:
    name: str
    points: int
    description: str

@dataclass(frozen=True)
class RiskResult:
    score: int
    level: RiskLevel
    indicators: List[Indicator] = field(default_factory=list)