<<<<<<< HEAD
# detectors/urls.py
# analyzes URLs found in email and flags suspicious patterns
# returns list of Indicator object that are used by the scoring engine
# Newly Added domain comparison between display anchor text and destination URLS

import re
from typing import List
from urllib.parse import urlparse
from models import Indicator, EmailMessage, logger

IP_HOST_REGEX = re.compile(r'https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
URL_DISCOVERY_REGEX = re.compile(r'https?:\/\/[^\s]+')

def scan_urls(email: EmailMessage) -> List[Indicator]:
    """Scans URLs for HTTP usage, raw IP hosts, and anchor text mismatches."""
    indicators = []
    
    for anchor, href in email.links:
        if href.startswith("http://"):
            indicators.append(
                Indicator(name="HTTP_URL", points=10, description=f"Non-HTTPS URL: {href}")
            )
            
        if IP_HOST_REGEX.match(href):
            indicators.append(
                Indicator(name="IP_URL", points=15, description=f"URL uses raw IP host: {href}")
            )
            
        # Detect Link Masking (Anchor display name mimics a different URL than href target)
        if URL_DISCOVERY_REGEX.match(anchor.strip()):
            anchor_domain = urlparse(anchor.strip()).netloc.lower()
            href_domain = urlparse(href).netloc.lower()
            
            if anchor_domain and href_domain and anchor_domain != href_domain:
                logger.info(f"Link spoofing detected: Anchor={anchor_domain} vs Href={href_domain}")
                indicators.append(
                    Indicator(
                        name="MISMATCHED_ANCHOR_URL",
                        points=25,
                        description=f"Deceptive link masking! Anchor shows '{anchor_domain}' but points to '{href_domain}'"
                    )
                )
                
=======
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
            
>>>>>>> 8bd1d38f5802b1da35f04e239778b5b0b3f0ece0
    return indicators