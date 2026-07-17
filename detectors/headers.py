from typing import List
from models import Indicator, EmailMessage

def scan_headers(email: EmailMessage) -> List[Indicator]:
    """Inspects headers for missing requirements or structural alignment."""
    indicators = []
    
    # Check 1: Missing standard 'Message-ID' (highly typical of custom script spam)
    if "Message-ID" not in email.headers:
        indicators.append(
            Indicator(
                name="MISSING_MESSAGE_ID",
                points=15,
                description="Email header is missing a standard Message-ID."
            )
        )
        
    # Check 2: Mismatched Reply-To field
    from_header = email.sender.lower()
    reply_to = email.headers.get("Reply-To", "").lower()
    
    if reply_to and reply_to not in from_header:
        indicators.append(
            Indicator(
                name="MISMATCHED_REPLY_TO",
                points=10,
                description=f"Reply-To address ({reply_to}) differs from From address."
            )
        )
        
    return indicators