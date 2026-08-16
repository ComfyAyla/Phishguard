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
            
    return indicators