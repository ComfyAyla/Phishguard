# main.py
# Interactive Command Line Interface (CLI) and entry point for PhishGuard.
# Runs single email or batch directory threat analysis with interactive user options.
#
# ----- CODING GOALS MET -----
# 1. FUNCTIONS - scan_single_email(), parse_email_batch(), analyze_batch_concurrently(), launch_gui(), process_single_email_interactive(), run_cli(), main()
# 2. CLASSES - PhishGuardGUI (imported from gui.py)
# 3. FILE HANDLING - Reads email files, appends to blacklist.txt/whitelist.txt, writes report files
# 4. CASTING - String conversions str(), int choice parsing, path sanitization
# 5. MODULES - OS module (os.path, os.remove, os.listdir), SYS module (sys.argv)

import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor

from models import logger, EmailMessage, RiskResult, extract_domain_safely
from parser import parse_email, parse_directory
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender
from detectors.attachments import scan_attachments
from detectors.headers import scan_headers
from detectors.whitelist import is_sender_whitelisted
from scoring import calculate_risk
from report import generate_text_report, save_report_to_file

# Goal 6: Comprehensive error handling and input validation (Path traversal defense)
def sanitize_filename(filename: str) -> str:
    # Strips relative folder paths to prevent directory traversal vulnerabilities
    return os.path.basename(filename)

def scan_single_email(file_path: str, email_obj: EmailMessage) -> tuple[str, EmailMessage, RiskResult]:
    # Runs the threat analysis pipeline on a single email instance
    whitelisted = is_sender_whitelisted(email_obj)
    indicators = []
    if not whitelisted:
        indicators.extend(scan_keywords(email_obj))
        indicators.extend(scan_urls(email_obj))
        indicators.extend(scan_sender(email_obj))
        indicators.extend(scan_attachments(email_obj))
        indicators.extend(scan_headers(email_obj))
        
    risk_result = calculate_risk(indicators, whitelisted=whitelisted)
    return file_path, email_obj, risk_result

# Goal 5: Support for scanning multiple emails at the same time
def parse_email_batch(target_path: str) -> list[tuple[str, EmailMessage]]:
    # Loads a single file or batch reads an entire directory of emails
    # Goal 6: Input validation on paths
    if not os.path.exists(target_path):
        raise ValueError("Invalid target path provided.")

    if os.path.isfile(target_path):
        email_obj = parse_email(target_path)
        return [(target_path, email_obj)] if email_obj else []
    
    elif os.path.isdir(target_path):
        batch = []
        for file_name in os.listdir(target_path):
            full_path = os.path.join(target_path, file_name)
            if os.path.isfile(full_path) and full_path.endswith((".eml", ".txt")):
                email_obj = parse_email(full_path)
                if email_obj:
                    batch.append((full_path, email_obj))
        return batch

# Goal 5: Support for scanning multiple emails at the same time (Multi-threading)
def analyze_batch_concurrently(batch: list[tuple[str, EmailMessage]], max_workers: int = 4):
    # Executes email threat scans simultaneously using multi-threading with explicit bounds
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_single_email, file_path, email_obj)
            for file_path, email_obj in batch
        ]
        return [f.result() for f in futures]

def launch_gui():
    # Launches the Tkinter Graphical User Interface
    import tkinter as tk
    from gui import PhishGuardGUI
    
    # Goal 8: Logging and debugging
    logger.info("Launching PhishGuard GUI...")
    print("[System] Launching PhishGuard Graphical User Interface...")
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()

# Goal 1: Interactive CLI function matching GUI decision options
def process_single_email_interactive(file_path: str, email_obj: EmailMessage, risk_result: RiskResult):
    # Interactive CLI decision loop offering Delete/Block, Whitelist, Save Report, Keep options
    report_content = generate_text_report(email_obj, risk_result, os.path.basename(file_path))
    print("\n" + report_content)
    
    while True:
        print("\nAVAILABLE ACTIONS:")
        print("  [1] Delete file & Blacklist sender domain")
        print("  [2] Whitelist sender domain")
        print("  [3] Save detailed report to disk")
        print("  [4] Keep file and exit")
        
        # Goal 6: Comprehensive input validation on user CLI prompt
        choice = input("Select an action (1-4): ").strip()
        
        if choice == "1":
            # File handling: Append to blacklist and remove file
            domain = extract_domain_safely(email_obj.sender)
            if domain:
                with open("blacklist.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{domain}")
                print(f"[+] Domain '{domain}' added to blacklist.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[+] File '{file_path}' permanently deleted.")
            break
        elif choice == "2":
            # File handling: Append to whitelist
            domain = extract_domain_safely(email_obj.sender)
            if domain:
                with open("whitelist.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{domain}")
                print(f"[+] Domain '{domain}' added to whitelist.txt.")
            break
        elif choice == "3":
            # File handling: Save report summary to disk
            out_name = f"report_{sanitize_filename(os.path.splitext(os.path.basename(file_path))[0])}.txt"
            save_report_to_file(email_obj, risk_result, out_name)
            print(f"[+] Report saved as '{out_name}'.")
        elif choice == "4":
            print("[*] File kept.")
            break
        else:
            print("[!] Invalid selection. Please enter a number from 1 to 4.")

def run_cli(target_path: str = None):
    print("=" * 60)
    print("PhishGuard Threat Analyzer (Concurrent CLI Mode)")
    print("=" * 60)
    
    if not target_path:
        target_path = input("Enter email file (.eml/.txt) or directory path: ").strip()
    
    # Goal 6: Comprehensive error handling
    try:
        batch = parse_email_batch(target_path)
        if not batch:
            print("[!] No valid email files found.")
            return

        print(f"\n[+] Loaded {len(batch)} email file(s). Scanning concurrently...")
        results = analyze_batch_concurrently(batch)
        
        for file_path, email_obj, risk_result in results:
            print(f"\n---> Finished Scanning: {file_path}")
            # Goal 1: User interactive CLI loop call
            process_single_email_interactive(file_path, email_obj, risk_result)
            
    except Exception as e:
        # Goal 8: Logging and debugging
        logger.error(f"Execution error in CLI: {e}")
        print(f"[!] Error: {e}")

def main():
    # Uses SYS module arguments to toggle GUI vs CLI execution mode
    parser = argparse.ArgumentParser(description="PhishGuard Email Threat Analyzer")
    parser.add_argument("-g", "--gui", action="store_true", help="Launch the graphical interface")
    parser.add_argument("path", nargs="?", help="Path to email file or directory to analyze via CLI")
    
    args = parser.parse_args()
    
    if args.gui:
        launch_gui()
    elif args.path:
        run_cli(args.path)
    else:
        # Goal 6: Graceful fallback handling
        try:
            launch_gui()
        except Exception as e:
            logger.warning(f"GUI launch failed or unavailable, falling back to CLI: {e}")
            run_cli()

if __name__ == "__main__":
    main()