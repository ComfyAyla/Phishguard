# detectors/urls.py
# Analyzes extracted links for non-HTTPS protocols, raw IP addresses, and link masking.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - scan_urls()
# 2. CLASSES - Indicator, EmailMessage (imported from models.py)
# 3. FILE HANDLING - N/A
# 4. CASTING - Typecasts anchors and URLs to str()
# 5. MODULES - urllib.parse module for domain isolation

import re
from typing import List
from urllib.parse import urlparse
from models import Indicator, EmailMessage, logger

IP_HOST_REGEX = re.compile(r'https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
URL_DISCOVERY_REGEX = re.compile(r'^(https?:\/\/|[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')

def scan_urls(email: EmailMessage) -> List[Indicator]:
    # Scans URLs for HTTP usage, raw IP hosts, and anchor text mismatches
    indicators = []
    if not email.links:
        return indicators
        
    for anchor, href in email.links:
        # Goal 6: Comprehensive input validation
        if not href or not isinstance(href, str):
            continue
            
        href = str(href).strip()
        if href.startswith("http://"):
            indicators.append(
                Indicator(name="HTTP_URL", points=10, description=f"Non-HTTPS URL: {href}")
            )
            
        if IP_HOST_REGEX.match(href):
            indicators.append(
                Indicator(name="IP_URL", points=15, description=f"URL uses raw IP host: {href}")
            )
            
        # Goal 3: Compare anchor text and actual destination URLs (Deceptive Link Masking)
        if anchor and isinstance(anchor, str):
            anchor_str = str(anchor).strip()
            if URL_DISCOVERY_REGEX.match(anchor_str):
                anchor_url = anchor_str if anchor_str.startswith(("http://", "https://")) else f"http://{anchor_str}"
                anchor_domain = urlparse(anchor_url).netloc.lower()
                href_domain = urlparse(href).netloc.lower()
                
                # Compare visible display text domain against actual destination domain
                if anchor_domain and href_domain and anchor_domain != href_domain:
                    # Goal 8: Logging and debugging
                    logger.info(f"Link spoofing detected: Anchor={anchor_domain} vs Href={href_domain}")
                    indicators.append(
                        Indicator(
                            name="MISMATCHED_ANCHOR_URL",
                            points=25,
                            description=f"Deceptive link masking! Anchor shows '{anchor_domain}' but points to '{href_domain}'"
                        )
                    )
                
    return indicators