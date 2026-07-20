# main.py
# CLI entry for the applications: it loads the email file, parses it, runs all the detectors, calculates the risk score
# finally it generates a text report and saves it to disk (hardcoded path)

import sys
import os

from parser import read_email_file, parse_email
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender
from detectors.attachments import scan_attachments  # <-- New
from detectors.headers import scan_headers          # <-- New
from scoring import calculate_risk
from report import generate_text_report, save_report_to_file

def run_analysis(file_path: str):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found!")
        return

    file_name = os.path.basename(file_path)
    raw_text = read_email_file(file_path)
    email_obj = parse_email(raw_text)
    
    # Run all detectors
    indicators = []
    indicators.extend(scan_keywords(email_obj))
    indicators.extend(scan_urls(email_obj))
    indicators.extend(scan_sender(email_obj))
    indicators.extend(scan_attachments(email_obj))  # <-- New
    indicators.extend(scan_headers(email_obj))      # <-- New
    
    risk_result = calculate_risk(indicators)
    report_content = generate_text_report(email_obj, risk_result, file_name)
    
    print(report_content)
    
    output_filename = f"report_{os.path.splitext(file_name)[0]}.txt"
    save_report_to_file(report_content, output_filename)
    print(f"\n[Success] Full report successfully saved as: '{output_filename}'")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_analysis(sys.argv[1])