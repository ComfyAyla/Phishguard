# models.py
# Core data models, dataclasses, enums, and centralized logging setup.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - extract_domain_safely()
# 2. CLASSES - RiskLevel(Enum), EmailMessage(dataclass), Indicator(dataclass), RiskResult(dataclass)
# 3. FILE HANDLING - Configures log file writing (phishguard.log)
# 4. CASTING - String manipulation str(), lower(), strip()
# 5. MODULES - Logging module configuration

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple

# Goal 8: Centralized logging and debugging configuration
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

# Goal 6: Safe domain extraction without vulnerable ReDoS regex loops
def extract_domain_safely(sender_string: str) -> str:
    """
    SECURITY FIX: ReDoS Prevention.
    Safely extracts a domain from an email string without vulnerable backtracking regex loops.
    """
    if not sender_string:
        return ""
        
    sender_lower = sender_string.lower().strip()
    if "@" in sender_lower:
        # Split from the right side once to isolate the domain part
        domain_part = sender_lower.rsplit("@", 1)[-1]
        
        # Clean out common email formatting characters like brackets or quotes
        domain_part = domain_part.strip(" <>()[]\"'")
        
        # Keep only valid domain letters, numbers, dots, and hyphens
        clean_domain = "".join(c for c in domain_part if c.isalnum() or c in ".-")
        return clean_domain
        
    return ""