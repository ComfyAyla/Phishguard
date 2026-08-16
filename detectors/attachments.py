#attachments.py
# analizes attachment filenames in an Emailmessage object and flags dangerous file extensions (defined below)
# Expanded attachment scanning foor compressed archives/evasive double extensions

import os
import re
from typing import List
from models import Indicator, EmailMessage, logger

DANGEROUS_EXTENSIONS = {
    ".exe": 25, ".scr": 25, ".bat": 20, ".vbs": 20, ".iso": 15,
    # Compressed Archives
    ".zip": 15, ".rar": 15, ".rzr": 15, ".7z": 15, ".tar": 10, ".gz": 10
}

DOUBLE_EXT_REGEX = re.compile(r'\.[a-z0-9]{2,4}\.(exe|scr|bat|vbs|ps1|jar)$', re.IGNORECASE)

def scan_attachments(email: EmailMessage) -> List[Indicator]:
    """Scans attachments for dangerous scripts, archives, and double extensions."""
    indicators = []
    
    for filename in email.attachments:
        fname_lower = filename.lower()
        _, ext = os.path.splitext(fname_lower)
        
        # Check 1: Dangerous or Compressed extension
        if ext in DANGEROUS_EXTENSIONS:
            pts = DANGEROUS_EXTENSIONS[ext]
            indicators.append(
                Indicator(
                    name=f"SUSPICIOUS_ATTACHMENT_{ext.upper()[1:]}",
                    points=pts,
                    description=f"High-risk attachment or archive type detected: '{filename}'"
                )
            )
            
        # Check 2: Double extension disguise (e.g. statement.pdf.exe)
        if DOUBLE_EXT_REGEX.search(fname_lower):
            logger.warning(f"Double extension masquerade detected: {filename}")
            indicators.append(
                Indicator(
                    name="DOUBLE_EXTENSION_ATTACHMENT",
                    points=30,
                    description=f"Evasive double extension detected in attachment: '{filename}'"
                )
            )
            
    return indicators