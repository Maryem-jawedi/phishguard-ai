import email
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class ParsedEmail:
    subject: str
    body: str
    sender: str
    sender_name: str
    sender_email: str
    urls: list[str]
    html_content: str
    headers: dict
    has_attachments: bool

def parse_email(raw_email: str) -> ParsedEmail:
    msg = email.message_from_string(raw_email)

    # -- sujet
    subject = msg.get("Subject", "") or ""

    # -- expéditeur
    sender_raw = msg.get("From", "") or ""
    sender_name, sender_email = _extract_sender(sender_raw)

    # -- corps et HTML
    body, html_content = _extract_body(msg)

    # -- URLs
    urls = _extract_urls(body + " " + html_content)

    # -- pièces jointes
    has_attachments = _has_attachments(msg)

    # -- headers complets
    headers = dict(msg.items())

    return ParsedEmail(
        subject=subject,
        body=body,
        sender=sender_raw,
        sender_name=sender_name,
        sender_email=sender_email,
        urls=urls,
        html_content=html_content,
        headers=headers,
        has_attachments=has_attachments,
    )


def _extract_sender(sender_raw: str):
    match = re.match(r'"?([^"<]*)"?\s*<?([^>]*)>?', sender_raw.strip())
    if match:
        name = match.group(1).strip()
        email_addr = match.group(2).strip()
        return name, email_addr
    return "", sender_raw.strip()


def _extract_body(msg) -> tuple[str, str]:
    body = ""
    html_content = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
            elif content_type == "text/html":
                html_content += part.get_payload(decode=True).decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    return body, html_content


def _extract_urls(text: str) -> list[str]:
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


def _has_attachments(msg) -> bool:
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            return True
    return False