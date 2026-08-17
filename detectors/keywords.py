# detectors/keywords.py
# Scans email subject and body content for psychological and financial threat vectors.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - scan_keywords()
# 2. CLASSES - EmailMessage, Indicator (imported from models.py)
# 3. FILE HANDLING - N/A (Handled via content parsing)
# 4. CASTING - Typecasts email fields to string str() and lowercase conversion
# 5. MODULES - OS module N/A, logging via models.py

from typing import List
from models import Indicator, EmailMessage, logger

# Goal 2: Advanced content and psychological triggers dictionary
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

    # Requests for PII (Personally Identifiable Information)
    "ssn": (20, "Social Security Number request"),
    "social security": (20, "PII harvesting attempt"),
    "password reset": (10, "Credential modification request"),
    "verify identity": (10, "Identity verification bait"),
    "confirm your account": (10, "Account credential harvesting")
}

def scan_keywords(email: EmailMessage) -> List[Indicator]:
    # Scans message content for psychological, financial, and PII threat vectors
    indicators = []
    
    # Goal 6: Input validation - sanitize against NoneType
    subject = str(email.subject or "").lower()
    body = str(email.body or "").lower()
    content = f"{subject} {body}"
    
    for term, (pts, desc) in PSYCHOLOGICAL_TRIGGERS.items():
        if term in content:
            # Goal 8: Debug logging
            logger.debug(f"Keyword trigger detected: '{term}' (+{pts} pts)")
            indicators.append(
                Indicator(
                    name=f"KEYWORD_{term.upper().replace(' ', '_')}",
                    points=pts,
                    description=f"{desc} (Trigger: '{term}')"
                )
            )
            
    return indicators