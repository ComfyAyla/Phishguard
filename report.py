# report.py
# Generates security threat analysis reports with actionable next steps and saves outputs to disk.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - generate_actionable_next_steps(), generate_text_report(), save_report_to_file()
# 2. CLASSES - EmailMessage, RiskResult (imported from models.py)
# 3. FILE HANDLING - Opens and writes reports with open(full_path, "w", encoding="utf-8")
# 4. CASTING - String typecasts str(), list formatting to string string.join()
# 5. MODULES - OS module (os.path.exists, os.makedirs, os.path.basename, os.path.abspath)

import os
from datetime import date
from models import EmailMessage, RiskResult

# Goal 7: Extra feature providing actionable next steps recommendations based on risk results
def generate_actionable_next_steps(result: RiskResult) -> list[str]:
    # Generates specific, dynamic actionable advice based on triggered threat indicators
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
        
    level_str = result.level.name if hasattr(result.level, "name") else str(result.level)
    if "HIGH" in level_str:
        steps.append("Report this message directly to your Security Operations Center (SOC).")
        steps.append("Delete the file permanently from disk and block the originating domain.")
    else:
        steps.append("Verify the sender's identity through out-of-band communication (phone/chat).")
        
    return steps

def generate_text_report(email: EmailMessage, result: RiskResult, file_name: str) -> str:
    # Formats full security audit text report with actionable next steps block
    current_date = date.today().strftime("%Y-%m-%d")
    sep = "—" * 100
    
    reply_to = email.headers.get("Reply-To", "None")
    links_str = "\n".join([f"{anchor} -> {href}" for anchor, href in email.links]) if email.links else "None"
    findings_str = "\n".join([f"[{ind.points} pts] {ind.name}: {ind.description}" for ind in result.indicators]) or "No flags."
    
    # Goal 7: Include actionable next steps in the generated report text
    next_steps = generate_actionable_next_steps(result)
    next_steps_str = "\n".join([f"- {step}" for step in next_steps])
    level_str = result.level.name if hasattr(result.level, "name") else str(result.level)

    return (
        f"{sep}\nPhishing Email Threat Analysis Report\nGenerated: {current_date} | File: {file_name}\n{sep}\n"
        f"Sender: {email.sender}\nReply-To: {reply_to}\nSubject: {email.subject}\n{sep}\n"
        f"Links Extracted:\n{links_str}\n{sep}\n"
        f"Security Indicators Triggered:\n{findings_str}\n{sep}\n"
        f"Risk Score: {result.score} | Risk Rating: {level_str}\n{sep}\n"
        f"ACTIONABLE NEXT STEPS:\n{next_steps_str}\n{sep}\n"
    )

def save_report_to_file(email: EmailMessage, result: RiskResult, file_name: str, output_dir: str = "reports") -> str:
    # Goal 6: Path sanitization and directory creation checks
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    clean_name = os.path.basename(file_name).replace(".", "_")
    output_filename = f"report_{clean_name}.txt"
    full_path = os.path.abspath(os.path.join(output_dir, output_filename))

    report_text = generate_text_report(email, result, file_name)

    # File handling: Write report output to disk
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return full_path