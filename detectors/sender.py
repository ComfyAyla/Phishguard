# detectors/sender.py
# analyzes sender's email address, to detect suspicous top-level domains and domains listed in blacklist.txt4
# returns Indicator objects taht are used in the grading engine

import os
import re
from typing import List
from models import Indicator, EmailMessage

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".gq", ".fit", ".tk"]

def load_blacklist() -> List[str]:
    """Helper to read the local blacklist.txt dynamically."""
    blacklist_path = "blacklist.txt"
    if not os.path.exists(blacklist_path):
        return []
    with open(blacklist_path, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

def scan_sender(email: EmailMessage) -> List[Indicator]:
    """Analyzes the sender domain, checking TLDs and local blacklist."""
    indicators = []
    
    # Extract email domain using regex
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email.sender)
    
    if email_match:
        domain = email_match.group(1).lower()
        sender_email = email.sender.lower()
        
        # Check 1: TLD Scan
        for tld in SUSPICIOUS_TLDS:
            if sender_email.endswith(tld):
                indicators.append(
                    Indicator(
                        name="SUSPICIOUS_TLD",
                        points=10,
                        description=f"Suspicious TLD ({tld}) in sender domain: {sender_email}"
                    )
                )
                break
                
        # Check 2: Blacklist Scan
        blacklist = load_blacklist()
        if domain in blacklist:
            indicators.append(
                Indicator(
                    name="BLACKLISTED_DOMAIN",
                    points=30,  # High points for explicit blacklist hit!
                    description=f"Sender domain ({domain}) is present on local threat blacklist!"
                )
            )
                
    return indicators