# detectors/sender.py
import os
import re
from typing import List
from models import Indicator, EmailMessage, logger

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".gq", ".fit", ".tk"]

def load_blacklist() -> List[str]:
    """Helper to read the local blacklist.txt safely."""
    blacklist_path = "blacklist.txt"
    if not os.path.exists(blacklist_path):
        return []
    try:
        with open(blacklist_path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Error reading {blacklist_path}: {e}")
        return []

def scan_sender(email: EmailMessage) -> List[Indicator]:
    """Analyzes the sender domain, checking TLDs and local blacklist."""
    indicators = []
    if not email.sender:
        return indicators
        
    sender_lower = email.sender.lower().strip()
    
    # Check 1: TLD Scan
    for tld in SUSPICIOUS_TLDS:
        if sender_lower.endswith(tld):
            indicators.append(
                Indicator(
                    name="SUSPICIOUS_TLD",
                    points=10,
                    description=f"Suspicious TLD ({tld}) in sender domain: {sender_lower}"
                )
            )
            break
            
    # Check 2: Blacklist Scan
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_lower)
    if email_match:
        domain = email_match.group(1).lower()
        blacklist = load_blacklist()
        if domain in blacklist:
            indicators.append(
                Indicator(
                    name="BLACKLISTED_DOMAIN",
                    points=30,
                    description=f"Sender domain ({domain}) is present on local threat blacklist!"
                )
            )
                
    return indicators