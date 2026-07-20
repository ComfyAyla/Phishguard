# detectors/urls.py
# analyzes URLs found in email and flags suspicious patterns
# returns list of Indicator object that are used by the scoring engine

import re
from typing import List
from models import Indicator, EmailMessage

# Regex to check if the hostname of a URL is a raw IP address (e.g., http://192.168.0.44/)
IP_HOST_REGEX = re.compile(r'https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

def scan_urls(email: EmailMessage) -> List[Indicator]:
    """Scans all links in the email for phishing indicators."""
    indicators = []
    
    for link in email.links:
        # Check 1: Using HTTP instead of HTTPS (highly suspicious for landing pages)
        if link.startswith("http://"):
            indicators.append(
                Indicator(
                    name="HTTP_URL",
                    points=10,
                    description=f"Non-HTTPS URL: {link}"
                )
            )
            
        # Check 2: Check if the link uses a raw IP address instead of a domain name
        if IP_HOST_REGEX.match(link):
            indicators.append(
                Indicator(
                    name="IP_URL",
                    points=15,
                    description=f"URL uses IP address host: {link}"
                )
            )
            
    return indicators