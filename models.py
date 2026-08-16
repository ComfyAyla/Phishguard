# Has added support for structured link objects --> enhanced indicator categorization
# models.py
# Contains core data models, enums, and centralized logging configuration for PhishGuard.

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple

# Centralized logging configuration
logging.basicConfig(
    filename="phishguard.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("PhishGuard")

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass(frozen=True)
class EmailMessage:
    sender: str
    subject: str
    body: str
    links: List[Tuple[str, str]] = field(default_factory=list)  # List of (anchor_text, href_url)
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
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