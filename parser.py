# parser.py
# Email file parser that processes raw .eml and .txt content into structured EmailMessage objects.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - extract_plain_text_urls(), parse_email(), parse_directory()
# 2. CLASSES - HTMLAnchorParser(HTMLParser), EmailMessage (imported from models.py)
# 3. FILE HANDLING - Opens email files in binary read mode 'rb'
# 4. CASTING - Converts raw headers/payloads using str(), decode()
# 5. MODULES - OS module (os.path.exists, os.listdir, os.path.join)

import os
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import List, Tuple, Optional

from models import EmailMessage, logger

# Goal 3: HTML Anchor parser upgraded to pair display anchor text with destination URL
class HTMLAnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: list):
        if tag.lower() == "a":
            self._current_href = None
            self._current_text = []
            for attr, value in attrs:
                if attr.lower() == "href" and value:
                    self._current_href = value

    def handle_data(self, data: str):
        if self._current_href is not None:
            # Goal 6: Memory boundary protection against oversized text buffers
            if len(self._current_text) < 50:
                self._current_text.append(data[:1000])

    def handle_endtag(self, tag: str):
        if tag.lower() == "a":
            if self._current_href is not None:
                anchor_text = "".join(self._current_text).strip()
                # Store tuple of (display_text, actual_destination_url)
                self.links.append((anchor_text, self._current_href))
            self._current_href = None
            self._current_text = []

def extract_plain_text_urls(text: str) -> List[Tuple[str, str]]:
    # Extracts raw URLs from plain text content safely
    url_pattern = re.compile(r'https?://[^\s<>"]+')
    found_urls = url_pattern.findall(text)
    return [(url, url) for url in found_urls]

def parse_email(file_path: str) -> Optional[EmailMessage]:
    # Goal 6: Input validation & error handling
    if not os.path.exists(file_path):
        # Goal 8: Centralized logging
        logger.error(f"File not found: {file_path}")
        return None

    try:
        # File handling: Binary file read mode
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        sender = str(msg.get("From", "") or "")
        subject = str(msg.get("Subject", "") or "")
        body = ""
        links: List[Tuple[str, str]] = []
        attachments: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", "") or "")

                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                elif content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            text_content = payload.decode(charset, errors="replace")
                            body += f"\n{text_content}"
                            links.extend(extract_plain_text_urls(text_content))
                    except Exception as e:
                        logger.warning(f"Error decoding text part in '{file_path}': {e}")

                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            html_content = payload.decode(charset, errors="replace")
                            anchor_parser = HTMLAnchorParser()
                            anchor_parser.feed(html_content)
                            links.extend(anchor_parser.links)
                    except Exception as e:
                        logger.warning(f"Error parsing HTML part in '{file_path}': {e}")
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    decoded_body = payload.decode(charset, errors="replace")
                    body = decoded_body
                    if content_type == "text/html":
                        anchor_parser = HTMLAnchorParser()
                        anchor_parser.feed(decoded_body)
                        links.extend(anchor_parser.links)
                    else:
                        links.extend(extract_plain_text_urls(decoded_body))
            except Exception as e:
                logger.warning(f"Error decoding email payload in '{file_path}': {e}")

        unique_links = []
        seen = set()
        for anchor, href in links:
            pair = (anchor, href)
            if pair not in seen:
                seen.add(pair)
                unique_links.append(pair)

        headers_dict = {k: str(v) for k, v in msg.items()}

        return EmailMessage(
            sender=sender,
            subject=subject,
            body=body.strip(),
            links=unique_links,
            attachments=attachments,
            headers=headers_dict
        )

    except Exception as err:
        # Goal 8: Logging malformed parse errors
        logger.error(f"Failed to parse email file '{file_path}': {err}")
        return None

# Goal 5: Batch directory parsing for scanning multiple emails
def parse_directory(directory_path: str) -> List[EmailMessage]:
    parsed_emails = []
    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        logger.error(f"Invalid directory path: {directory_path}")
        return parsed_emails

    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path):
            try:
                email_obj = parse_email(file_path)
                if email_obj:
                    parsed_emails.append(email_obj)
            except Exception as err:
                logger.error(f"Skipping malformed email '{file_name}': {err}")

    logger.info(f"Batch parsed {len(parsed_emails)} email(s) from '{directory_path}'")
    return parsed_emails