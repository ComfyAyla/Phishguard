# extractor.py
# Responsible for finding URLs, extracts the sender string from the headers
# it can handle domain-based URLs and IP-based URLs
# it also supports defanged formats that are used in malware analysis (ex: hxxp -> http; [.] -> .; [:] -> :) - allows it to detect URLs even when attackers try to hide them

import re
from typing import List

# Updated regex to allow bracketed colons '[:]' or ':', and bracketed dots '[.]' or '.'
URL_REGEX = re.compile(
    r'(?:https?|hxxps?)(?:\[:\]|:)\/\/'           # Scheme with optional bracketed colon
    r'(?:[a-zA-Z0-9\-]+(?:\[\.\]|\.))+'           # Domain with optional bracketed dot
    r'[a-zA-Z]{2,}'                               # TLD
    r'(?::\d+)?'                                  # Optional Port
    r'(?:\/[^\s"\'<>]*)*'                         # Path & query
    r'|'
    r'(?:https?|hxxps?)(?:\[:\]|:)\/\/\d{1,3}(?:(?:\[\.\]|\.)\d{1,3}){3}(?::\d+)?(?:\/[^\s"\'<>]*)*' # IP Host
)

def extract_links(text: str) -> List[str]:
    """Finds all URLs inside a text payload, normalizing defanged formats."""
    if not text:
        return []
    
    found = URL_REGEX.findall(text)
    normalized = []
    for url in found:
        # Normalize defanged schemas first
        norm_url = url.replace("hxxps", "https").replace("hxxp", "http")
        # Strip brackets from [.] and [:]
        norm_url = norm_url.replace("[.]", ".").replace("[:]", ":")
        
        if norm_url not in normalized:
            normalized.append(norm_url)
            
    return normalized

def extract_sender(from_header: str) -> str:
    """Cleans up and extracts the raw 'From' string or returns fallback."""
    return from_header.strip() if from_header else "Unknown Sender"