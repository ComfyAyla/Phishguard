# whitelist.py
import os
import re
from typing import List
from models import EmailMessage, logger

def load_whitelist() -> List[str]:
    """Helper to read local whitelist.txt safely."""
    whitelist_path = "whitelist.txt"
    if not os.path.exists(whitelist_path):
        return []
    try:
        with open(whitelist_path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Error reading {whitelist_path}: {e}")
        return []

def is_sender_whitelisted(email: EmailMessage) -> bool:
    """Checks if sender's exact email address or exact domain is whitelisted."""
    whitelist = load_whitelist()
    if not whitelist or not email.sender:
        return False
        
    sender_lower = email.sender.lower().strip()
    
    # Check 1: Direct exact email address match
    if sender_lower in whitelist:
        return True
            
    # Check 2: Extract domain and check exact domain match
    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_lower)
    if email_match:
        domain = email_match.group(1).lower()
        if domain in whitelist:
            return True
            
    return False