# Updated report with context-aware, and actionable remediation recommendations.

from datetime import date
from models import EmailMessage, RiskResult

def generate_actionable_next_steps(result: RiskResult) -> list[str]:
    """Generates specific, dynamic actionable advice based on triggered threat indicators."""
    steps = ["Do not click any embedded links or open unexpected attachments."]
    
    indicator_names = [ind.name for ind in result.indicators]
    
    if any("KEYWORD_SSN" in n or "KEYWORD_VERIFY" in n or "KEYWORD_BANK" in n for n in indicator_names):
        steps.append("DO NOT share personal identity info (PII), SSN, or banking credentials.")
        steps.append("If credentials were provided, immediately reset passwords and notify IT.")
        
    if any("ATTACHMENT" in n for n in indicator_names):
        steps.append("Do not extract or execute attached archives (.zip, .7z) or script files.")
        steps.append("Submit suspicious attachments to your IT Security sandbox for analysis.")
        
    if any("MISMATCHED_ANCHOR_URL" in n or "IP_URL" in n for n in indicator_names):
        steps.append("Flag deceptive link masking to your network security team for domain blocking.")
        
    if result.level == "HIGH":
        steps.append("Report this message directly to your Security Operations Center (SOC).")
        steps.append("Delete the file permanently from disk and block the originating domain.")
    else:
        steps.append("Verify the sender's identity through out-of-band communication (phone/chat).")
        
    return steps

def generate_text_report(email: EmailMessage, result: RiskResult, file_name: str) -> str:
    """Generates full security audit text report with next steps."""
    current_date = date.today().strftime("%Y-%m-%d")
    sep = "—" * 100
    
    reply_to = email.headers.get("Reply-To", "None")
    links_str = "\n".join([f"{anchor} -> {href}" for anchor, href in email.links]) if email.links else "None"
    findings_str = "\n".join([f"[{ind.points} pts] {ind.name}: {ind.description}" for ind in result.indicators]) or "No flags."
    
    next_steps = generate_actionable_next_steps(result)
    next_steps_str = "\n".join([f"- {step}" for step in next_steps])

    return (
        f"{sep}\nPhishing Email Threat Analysis Report\nGenerated: {current_date} | File: {file_name}\n{sep}\n"
        f"Sender: {email.sender}\nReply-To: {reply_to}\nSubject: {email.subject}\n{sep}\n"
        f"Links Extracted:\n{links_str}\n{sep}\n"
        f"Security Indicators Triggered:\n{findings_str}\n{sep}\n"
        f"Risk Score: {result.score} | Risk Rating: {result.level}\n{sep}\n"
        f"ACTIONABLE NEXT STEPS:\n{next_steps_str}\n{sep}\n"
    )

def save_report_to_file(report_text: str, output_path: str):
    """Saves report cleanly to disk with sanitized paths."""
    safe_path = os.path.abspath(output_path)
    with open(safe_path, "w", encoding="utf-8") as f:
        f.write(report_text)