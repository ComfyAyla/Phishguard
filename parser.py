<<<<<<< HEAD
# HTML extraction to capture anchor tent wih destination URLS
    # Added batch scanning for directories
import os
import email
from html.parser import HTMLParser
from typing import List, Tuple, Dict
from models import EmailMessage, logger
from extractor import extract_links

class HTMLAnchorParser(HTMLParser):
    """Extracts (anchor_text, href) pairs from HTML body parts."""
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self.current_href = None
        self.current_text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            attrs_dict = dict(attrs)
            self.current_href = attrs_dict.get('href', '').strip()
            self.current_text = []

    def handle_data(self, data):
        if self.current_href is not None:
            self.current_text.append(data.strip())

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self.current_href is not None:
            anchor_text = " ".join(filter(None, self.current_text))
            self.links.append((anchor_text, self.current_href))
            self.current_href = None
            self.current_text = []

def read_email_file(file_path: str) -> str:
    """Reads email content safely with validation."""
    abs_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Specified path is not a file: {file_path}")
    
    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def parse_email(raw_content: str) -> EmailMessage:
    """Parses raw email content, extracting headers, attachments, and link metadata."""
    try:
        msg = email.message_from_string(raw_content)
        headers: Dict[str, str] = {k: v for k, v in msg.items()}
        sender = headers.get("From", "Unknown Sender")
        subject = headers.get("Subject", "(No Subject)")
        
        body_parts: List[str] = []
        extracted_links: List[Tuple[str, str]] = []
        attachments: List[str] = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                filename = part.get_filename()
                
                if "attachment" in content_disposition or filename:
                    if filename:
                        attachments.append(filename)
                elif content_type in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode('utf-8', errors='ignore')
                        body_parts.append(decoded)
                        if content_type == "text/html":
                            html_parser = HTMLAnchorParser()
                            html_parser.feed(decoded)
                            extracted_links.extend(html_parser.links)
                        else:
                            plain_urls = extract_links(decoded)
                            extracted_links.extend([(url, url) for url in plain_urls])
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode('utf-8', errors='ignore')
                body_parts.append(decoded)
                plain_urls = extract_links(decoded)
                extracted_links.extend([(url, url) for url in plain_urls])

        combined_body = "\n".join(body_parts)
        unique_links = list(dict.fromkeys(extracted_links))
        
        return EmailMessage(
            sender=sender, subject=subject, body=combined_body,
            links=unique_links, headers=headers, attachments=attachments, raw=raw_content
        )
    except Exception as e:
        logger.error(f"Error parsing email message: {e}")
        raise ValueError(f"Malformed email content: {e}")

def parse_email_batch(target_path: str) -> List[Tuple[str, EmailMessage]]:
    """Supports single file or directory batch loading."""
    target_path = os.path.abspath(target_path)
    results = []
    
    if os.path.isfile(target_path):
        raw = read_email_file(target_path)
        results.append((target_path, parse_email(raw)))
    elif os.path.isdir(target_path):
        for root_dir, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.eml', '.txt')):
                    full_p = os.path.join(root_dir, file)
                    try:
                        raw = read_email_file(full_p)
                        results.append((full_p, parse_email(raw)))
                    except Exception as err:
                        logger.warning(f"Skipping unparseable file {full_p}: {err}")
    else:
        raise ValueError("Invalid target path provided.")
        
    return results
=======
# parser.py
# reads raw .eml file and parses it into an EmailMessage dataclass (that we made ourselves)
# extracts headers, dender, subject, body text, links, attachments

import email
from email.message import Message
from typing import Dict, List
from models import EmailMessage
from extractor import extract_links

# oepn file, read contents at text, return as raw string
def read_email_file(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

# convert raw text into Message object, allows access to headers/body parts/attachments 
def parse_email(raw_content: str) -> EmailMessage:
    msg: Message = email.message_from_string(raw_content)
    headers: Dict[str, str] = {k: v for k, v in msg.items()}
    sender = headers.get("From", "Unknown Sender")
    subject = headers.get("Subject", "(No Subject)")
    
    body_parts: List[str] = []
    links: List[str] = []
    attachments: List[str] = []  # <-- Track attachment names
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            filename = part.get_filename()
            
            # Check if this part is an attachment
            if "attachment" in content_disposition or filename:
                if filename:
                    attachments.append(filename)
            else:
                # This is standard body text/html
                if content_type in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        body_parts.append(payload)
                        links.extend(extract_links(payload))
                    except Exception:
                        continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded_payload = payload.decode('utf-8', errors='ignore')
            body_parts.append(decoded_payload)
            links.extend(extract_links(decoded_payload))

    combined_body = "\n".join(body_parts)
    unique_links = list(dict.fromkeys(links))
    
    return EmailMessage(
        sender=sender,
        subject=subject,
        body=combined_body,
        links=unique_links,
        headers=headers,
        attachments=attachments,  # <-- Pass attachments to our object
        raw=raw_content
    )
>>>>>>> 8bd1d38f5802b1da35f04e239778b5b0b3f0ece0
