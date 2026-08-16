<<<<<<< HEAD
# detectors/keywords.py
# scans the subject andbody of email for suspicious keywords (defined below)
# it generates Indicator objects that contribute to final risk score
# Expanded keyword detection to cover common psychological urgency, finacial requests and PII harvesting tiggers
from typing import List
from models import Indicator, EmailMessage, logger

PSYCHOLOGICAL_TRIGGERS = {
    # Urgency & Threatening Language
    "urgent": (5, "Urgent action requested"),
    "immediate action required": (10, "High urgency pressure tactic"),
    "account suspended": (10, "Threat of service disruption"),
    "account locked": (10, "Threat of access loss"),
    "security alert": (5, "Security alarm trigger"),
    "legal action": (15, "Coercive legal threat"),
    "unauthorized login": (10, "Panic-inducing security trigger"),
    
    # Financial Transactions
    "wire transfer": (15, "Financial transfer request"),
    "gift card": (20, "Untraceable payment request"),
    "invoice attached": (10, "Financial obligation pressure"),
    "overdue payment": (10, "Financial penalty pressure"),
    "bank details": (15, "Financial credential request"),
    "direct deposit": (15, "Payroll/financial modification request"),

    # PII Requests
    "ssn": (20, "Social Security Number request"),
    "social security": (20, "PII harvesting attempt"),
    "password reset": (10, "Credential modification request"),
    "verify identity": (10, "Identity verification bait"),
    "confirm your account": (10, "Account credential harvesting")
}

def scan_keywords(email: EmailMessage) -> List[Indicator]:
    """Scans message content for psychological, financial, and PII threat vectors."""
    indicators = []
    content = f"{email.subject} {email.body}".lower()
    
    for term, (pts, desc) in PSYCHOLOGICAL_TRIGGERS.items():
        if term in content:
            logger.debug(f"Keyword trigger detected: '{term}' (+{pts} pts)")
            indicators.append(
                Indicator(
                    name=f"KEYWORD_{term.upper().replace(' ', '_')}",
                    points=pts,
                    description=f"{desc} (Trigger: '{term}')"
                )
            )
            
=======
# detectors/keywords.py
# scans the subject andbody of email for suspicious keywords (defined below)
# it generates Indicator objects that contribute to final risk score

from typing import List
from models import Indicator, EmailMessage

SUSPICIOUS_KEYWORDS = {
    "urgent": 5,
    "verify": 5,
    "account locked": 5,
    "click here": 5,
    "suspicious activity": 5,
    "security alert": 5,
    "immediate action": 10,
    "password reset": 5
}

def scan_keywords(email: EmailMessage) -> List[Indicator]:
    """Scans the subject and body for classic phishing keywords."""
    indicators = []
    
    # Combine subject and body and convert to lowercase for case-insensitive matching
    content_to_scan = f"{email.subject} {email.body}".lower()
    
    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in content_to_scan:
            indicators.append(
                Indicator(
                    name=f"KEYWORD_{keyword.upper().replace(' ', '_')}",
                    points=points,
                    description=f"Suspicious keyword found: '{keyword}'"
                )
            )
            
>>>>>>> 8bd1d38f5802b1da35f04e239778b5b0b3f0ece0
    return indicators