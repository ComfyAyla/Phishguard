# report.py
from datetime import date
from typing import List
from models import EmailMessage, RiskResult

def generate_text_report(email: EmailMessage, result: RiskResult, file_name: str) -> str:
    """Generates a highly structured phishing analysis report string."""
    
    # 1. Prepare Header Metadata
    current_date = date.today().strftime("%Y-%m-%d")
    separator = "—" * 120
    short_separator = "—" * 44
    
    # Extract Reply-To header cleanly
    reply_to = email.headers.get("Reply-To", "None")

    # 2. Format Links Section
    links_section = "None"
    if email.links:
        links_section = "\n".join(email.links)

    # 3. Format Triggered Indicators (Findings)
    findings_list = []
    scoring_breakdown = []
    for ind in result.indicators:
        # e.g., "Urgent / Threatening Language: Suspicious keyword found..."
        findings_list.append(f"{ind.name.replace('_', ' ').title()}: {ind.description}")
        # e.g., "Urgent language         +5"
        clean_name = ind.name.replace("KEYWORD_", "").replace("_", " ").title()
        scoring_breakdown.append(f"{clean_name:<24} +{ind.points}")
    
    findings_section = "\n".join(findings_list) if findings_list else "No highly suspicious patterns detected."
    scoring_section = "\n".join(scoring_breakdown) if scoring_breakdown else "No risk points accumulated."

    # 4. Generate Dynamic Summary based on Risk Level
    if result.level == "HIGH":
        summary = (
            "This email showcases several high-risk phishing characteristics, including high-pressure language, "
            "suspicious sender domains, or deceptive links designed to compromise your credentials. "
            "The email should be treated as a severe security threat and must not be interacted with."
        )
    elif result.level == "MEDIUM":
        summary = (
            "This email displays moderate risk characteristics. While it may not contain obvious malicious payloads, "
            "the combination of urgent phrasing or unexpected links warrants caution. Verify through external channels."
        )
    else:
        summary = (
            "This email displays low-risk characteristics and did not trigger major security indicators. "
            "However, always exercise standard caution when clicking links or downloading attachments."
        )

    # 5. Build the visual report block by block
    report_lines = [
        separator,
        "Possible Phishing Email Detected - Report",
        f"Generated: {current_date}",
        f"Analyzed File: {file_name}",
        separator,
        f"Sender: {email.sender}",
        f"Reply-To: {reply_to}",
        f"Subject: {email.subject}",
        separator,
        "Links Found: ",
        links_section,
        separator,
        findings_section,
        separator,
        "Risk Rating:",
        scoring_section,
        short_separator,
        f"Total Risk Rating: {result.score} – {result.level}",
        separator,
        "Summary:",
        summary,
        separator,
        "Recommended Action(s)",
        "Do not click any links provided",
        "Do not reply",
        "Report to your security team",
        "Delete the email from the inbox",
        separator,
        "Would you like to Delete this email and block the sender?",
        f"{'YES':<12}{'NO':<8}Whitelist the Sender",
        separator
    ]

    return "\n".join(report_lines)


def save_report_to_file(report_text: str, output_path: str):
    """Saves the generated report to a specified text file path."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)