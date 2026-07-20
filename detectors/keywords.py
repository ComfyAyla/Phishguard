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
            
    return indicators