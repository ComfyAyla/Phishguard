# extractor.py
# Responsible for finding URLs, extracts the sender string from the headers
# it can handle domain-based URLs and IP-based URLs
# it also supports defanged formats that are used in malware analysis (ex: hxxp -> http; [.] -> .; [:] -> :) - allows it to detect URLs even when attackers try to hide them

import re
from typing import List

# SECURITY FIX: ReDoS protection. Simplified validation constraints to prevent catastrophic backtracking.
URL_REGEX = re.compile(r'(?:https?|hxxps?)(?:\[:\]|:)\/\/[^\s"\'<>]+', re.IGNORECASE)

def extract_links(text: str) -> List[str]:
    """Finds all URLs inside a text payload, normalizing defanged formats securely."""
    if not text:
        return []
    
    found = URL_REGEX.findall(text)
    normalized = []
    for url in found:
        # Normalize defanged schemas
        norm_url = url.replace("hxxps", "https").replace("hxxp", "http")
        norm_url = norm_url.replace("HXXPS", "https").replace("HXXP", "http")
        
        # Strip brackets from [.] and [:] safely
        norm_url = norm_url.replace("[.]", ".").replace("[:]", ":")
        
        if norm_url not in normalized:
            normalized.append(norm_url)
            
    return normalized

def extract_sender(from_header: str) -> str:
    """Cleans up and extracts the raw 'From' string safely."""
    return from_header.strip() if from_header else "Unknown Sender"
