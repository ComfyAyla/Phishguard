import os
import re
from typing import List
from models import EmailMessage

def load_whitelist() -> List[str]:
    """Helper to read the local whitelist.txt dynamically."""
    whitelist_path = "whitelist.txt"
    if not os.path.exists(whitelist_path):
        return []
    with open(whitelist_path, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

def is_sender_whitelisted(email: EmailMessage) -> bool:
    """Checks if the sender's email or domain is on the local whitelist."""
    whitelist = load_whitelist()
    if not whitelist:
        return False
        
    sender_lower = email.sender.lower()
    
    # Check if direct email address matches
    for entry in whitelist:
        if entry in sender_lower:
            return True
            
    # Extract domain using regex
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email.sender)
    if email_match:
        domain = email_match.group(1).lower()
        if domain in whitelist:
            return True
            
    return False
