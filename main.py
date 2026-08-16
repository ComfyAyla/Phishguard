<<<<<<< HEAD
# Both terminal and gui interactive
# Combined app.py into main
import sys
import os
import re
import argparse

from models import logger
from parser import parse_email_batch
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender
from detectors.attachments import scan_attachments
from detectors.headers import scan_headers
from detectors.whitelist import is_sender_whitelisted
from scoring import calculate_risk
from report import generate_text_report, save_report_to_file

def sanitize_filename(filename: str) -> str:
    """Security audit fix: Path traversal defense."""
    return os.path.basename(filename)

def launch_gui():
    """Launches the Tkinter Graphical User Interface."""
    import tkinter as tk
    from gui import PhishGuardGUI
    
    logger.info("Launching PhishGuard GUI...")
    print("[System] Launching PhishGuard Graphical User Interface...")
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()

def process_single_email_interactive(file_path: str, email_obj):
    """Interactive CLI loop matching the GUI decision pipeline."""
    whitelisted = is_sender_whitelisted(email_obj)
    indicators = []
    if not whitelisted:
        indicators.extend(scan_keywords(email_obj))
        indicators.extend(scan_urls(email_obj))
        indicators.extend(scan_sender(email_obj))
        indicators.extend(scan_attachments(email_obj))
        indicators.extend(scan_headers(email_obj))
        
    risk_result = calculate_risk(indicators, whitelisted=whitelisted)
    report_content = generate_text_report(email_obj, risk_result, os.path.basename(file_path))
    
    print("\n" + report_content)
    
    while True:
        print("\nAVAILABLE ACTIONS:")
        print("  [1] Delete file & Blacklist sender domain")
        print("  [2] Whitelist sender domain")
        print("  [3] Save detailed report to disk")
        print("  [4] Keep file and exit")
        choice = input("Select an action (1-4): ").strip()
        
        if choice == "1":
            email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_obj.sender)
            if email_match:
                domain = email_match.group(1).lower()
                with open("blacklist.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{domain}")
                print(f"[+] Domain '{domain}' added to blacklist.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[+] File '{file_path}' permanently deleted.")
            break
        elif choice == "2":
            email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_obj.sender)
            if email_match:
                domain = email_match.group(1).lower()
                with open("whitelist.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{domain}")
                print(f"[+] Domain '{domain}' added to whitelist.txt.")
            break
        elif choice == "3":
            out_name = f"report_{sanitize_filename(os.path.splitext(os.path.basename(file_path))[0])}.txt"
            save_report_to_file(report_content, out_name)
            print(f"[+] Report saved as '{out_name}'.")
        elif choice == "4":
            print("[*] File kept.")
            break
        else:
            print("[!] Invalid selection.")

def run_cli(target_path: str = None):
    print("=" * 60)
    print(" 🛡️ PhishGuard Threat Analyzer (CLI Mode)")
    print("=" * 60)
    
    if not target_path:
        target_path = input("Enter email file (.eml/.txt) or directory path: ").strip()
    
    try:
        batch = parse_email_batch(target_path)
        print(f"\n[+] Loaded {len(batch)} email file(s) for analysis.")
        
        for file_path, email_obj in batch:
            print(f"\n---> Analyzing: {file_path}")
            process_single_email_interactive(file_path, email_obj)
            
    except Exception as e:
        logger.error(f"Execution error in CLI: {e}")
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="PhishGuard Email Threat Analyzer")
    parser.add_argument("-g", "--gui", action="store_true", help="Launch the graphical interface")
    parser.add_argument("path", nargs="?", help="Path to email file or directory to analyze via CLI")
    
    args = parser.parse_args()
    
    if args.gui:
        launch_gui()
    elif args.path:
        run_cli(args.path)
    else:
        # Default behavior: launch GUI if available, otherwise prompt CLI
        try:
            launch_gui()
        except Exception as e:
            logger.warning(f"GUI launch failed or unavailable, falling back to CLI: {e}")
            run_cli()

if __name__ == "__main__":
    main()
=======
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
>>>>>>> 8bd1d38f5802b1da35f04e239778b5b0b3f0ece0
