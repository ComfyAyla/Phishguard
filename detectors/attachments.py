#attachments.py
# analizes attachment filenames in an Emailmessage object and flags dangerous file extensions (defined below)


import os
from typing import List
from models import Indicator, EmailMessage

# High-risk executable or script extensions
DANGEROUS_EXTENSIONS = {
    ".exe": 25,  # Executables
    ".scr": 25,  # Screensavers (highly malicious)
    ".bat": 20,  # Batch scripts
    ".vbs": 20,  # VBS scripts
    ".zip": 10,  # Archives (often obfuscate malware)
    ".iso": 15   # Disk images
}

def scan_attachments(email: EmailMessage) -> List[Indicator]:
    """Scans attachment file names for high-risk extensions."""
    indicators = []
    
    for filename in email.attachments:
        _, ext = os.path.splitext(filename.lower())
        if ext in DANGEROUS_EXTENSIONS:
            points = DANGEROUS_EXTENSIONS[ext]
            indicators.append(
                Indicator(
                    name=f"SUSPICIOUS_ATTACHMENT_{ext.upper()[1:]}",
                    points=points,
                    description=f"Dangerous attachment extension found: '{filename}'"
                )
            )
            
    return indicators