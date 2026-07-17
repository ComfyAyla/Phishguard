import email
from email.message import Message
from typing import Dict, List
from models import EmailMessage
from extractor import extract_links

def read_email_file(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

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