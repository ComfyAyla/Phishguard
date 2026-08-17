# PhishGuardGUI class
# this class handles the front-end of the application through Tkinter module
# It builds the GUI layout, loads the .eml/.txt files, runs the background detectors, displays sender/subject/links/attachemts, shows risk score and indicators, and options for the user to delete/keep/whitelist/save report

#   ----- CODING REQUIREMENTS MET ----- 
# 1. FUNCTIONS - everywhere
# 2. CLASSE - PhishGuardGUI
# 3. FILE HANDLING - in functions save_report_dialog(), generate_text_report(), action_whitelist(), action_delete() etc.
#       File handling is through OS module
# 4. CASTING - typecasts to string str(e), regex extraction to string, list to string writing
# 5. MODULE - OS module is used

import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor

# Import backend modules
from parser import parse_email
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender
from detectors.attachments import scan_attachments
from detectors.headers import scan_headers
from detectors.whitelist import is_sender_whitelisted
from scoring import calculate_risk
from report import save_report_to_file


class PhishGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard - Interactive Email Threat Analyzer")
        self.root.geometry("1100x880")
        self.root.configure(bg="#1e1e2e")

        self.batch_results = []  # Stores tuples of (file_path, parsed_email, risk_result)
        self.current_index = -1

        self.current_file_path = None
        self.parsed_email = None
        self.risk_result = None

        self.setup_styles()
        self.build_ui()

    def setup_styles(self):
        """Set up modern colors and styles using ttk."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TFrame", background="#1e1e2e")
        self.style.configure("Card.TFrame", background="#252538", borderwidth=1, relief="solid")
        self.style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background="#1e1e2e", foreground="#f5c2e7", font=("Segoe UI", 14, "bold"))
        self.style.configure("Sub.TLabel", background="#252538", foreground="#bac2de", font=("Segoe UI", 10, "bold"))
        self.style.configure("Body.TLabel", background="#252538", foreground="#cdd6f4", font=("Segoe UI", 10))
        self.style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), padding=6)

    def build_ui(self):
        """Builds the window structure layout."""
        top_frame = ttk.Frame(self.root, padding=15)
        top_frame.pack(fill="x")

        title_lbl = ttk.Label(top_frame, text="🛡️ PhishGuard Email Scanner", style="Header.TLabel")
        title_lbl.pack(side="left")

        self.browse_btn = tk.Button(
            top_frame,
            text="📁 Browse Email Files (.eml / .txt)",
            command=self.browse_files,
            bg="#89b4fa", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.browse_btn.pack(side="right")

        # Batch Navigation Bar
        nav_frame = ttk.Frame(self.root, padding=(15, 0, 15, 5))
        nav_frame.pack(fill="x")

        ttk.Label(nav_frame, text="Scanned Batch Files:", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 10))

        self.file_selector = ttk.Combobox(nav_frame, state="readonly", font=("Segoe UI", 10))
        self.file_selector.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.file_selector.bind("<<ComboboxSelected>>", self.on_email_selected)

        self.batch_count_lbl = ttk.Label(nav_frame, text="0 files loaded", font=("Segoe UI", 10, "italic"))
        self.batch_count_lbl.pack(side="right")

        main_pane = ttk.Frame(self.root, padding=10)
        main_pane.pack(fill="both", expand=True)

        left_col = ttk.Frame(main_pane)
        left_col.pack(side="left", fill="both", expand=True, padx=5)

        # Email Metadata Card
        meta_card = ttk.Frame(left_col, style="Card.TFrame", padding=12)
        meta_card.pack(fill="x", pady=5)

        ttk.Label(meta_card, text="EMAIL DETAILS", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.sender_lbl = ttk.Label(meta_card, text="Sender: --", style="Body.TLabel")
        self.sender_lbl.pack(anchor="w")
        self.reply_lbl = ttk.Label(meta_card, text="Reply-To: --", style="Body.TLabel")
        self.reply_lbl.pack(anchor="w")
        self.subject_lbl = ttk.Label(meta_card, text="Subject: --", style="Body.TLabel")
        self.subject_lbl.pack(anchor="w")

        # Attachments Card
        attachments_card = ttk.Frame(left_col, style="Card.TFrame", padding=12)
        attachments_card.pack(fill="x", pady=5)

        ttk.Label(attachments_card, text="ATTACHMENTS", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.attachments_text = tk.Text(attachments_card, bg="#181825", fg="#fab387", font=("Consolas", 10), height=3, relief="flat")
        self.attachments_text.pack(fill="x", expand=True)
        self.attachments_text.insert(tk.END, "No attachments detected.")

        # Extracted Links Card
        links_card = ttk.Frame(left_col, style="Card.TFrame", padding=12)
        links_card.pack(fill="both", expand=True, pady=5)

        ttk.Label(links_card, text="EXTRACTED LINKS", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.links_text = tk.Text(links_card, bg="#181825", fg="#a6e3a1", insertbackground="white", font=("Consolas", 10), height=6, relief="flat")
        self.links_text.pack(fill="both", expand=True)

        right_col = ttk.Frame(main_pane)
        right_col.pack(side="right", fill="both", expand=True, padx=5)

        # Score Widget Card
        score_card = ttk.Frame(right_col, style="Card.TFrame", padding=12)
        score_card.pack(fill="x", pady=5)

        ttk.Label(score_card, text="RISK RATING", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.score_val_lbl = tk.Label(score_card, text="SCORE: 00 - UNDETERMINED", bg="#252538", fg="#ffffff", font=("Consolas", 12, "bold"))
        self.score_val_lbl.pack(fill="x", pady=5)

        # Triggered Indicators List Card
        indicators_card = ttk.Frame(right_col, style="Card.TFrame", padding=12)
        indicators_card.pack(fill="both", expand=True, pady=5)

        ttk.Label(indicators_card, text="SECURITY INDICATORS & POINT BREAKDOWN", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.indicators_text = tk.Text(indicators_card, bg="#181825", fg="#f3ba88", insertbackground="white")
        self.indicators_text.pack(fill="both", expand=True)

        # Footer Actions
        footer_frame = ttk.Frame(self.root, padding=15)
        footer_frame.pack(fill="x")

        prompt_lbl = ttk.Label(footer_frame, text="Would you like to Delete this email and block the sender?", font=("Segoe UI", 11, "bold"))
        prompt_lbl.pack(side="top", anchor="center", pady=(0, 10))

        btn_row = ttk.Frame(footer_frame)
        btn_row.pack(side="top", anchor="center")

        self.btn_yes = tk.Button(btn_row, text="🔴 YES, DELETE & BLOCK", bg="#f38ba8", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5, command=self.action_delete)
        self.btn_yes.pack(side="left", padx=10)

        self.btn_no = tk.Button(btn_row, text="⚪ NO, KEEP", bg="#a6e3a1", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5, command=self.action_keep)
        self.btn_no.pack(side="left", padx=10)

        self.btn_whitelist = tk.Button(btn_row, text="🛡️ WHITELIST SENDER", bg="#cba6f7", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5, command=self.action_whitelist)
        self.btn_whitelist.pack(side="left", padx=10)

        self.btn_save_report = tk.Button(btn_row, text="💾 SAVE REPORT", bg="#fab387", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5, command=self.save_report_dialog)
        self.btn_save_report.pack(side="left", padx=10)

    def browse_files(self):
        """Open a file dialog allowing multi-selection of email files."""
        file_paths = filedialog.askopenfilenames(
            title="Select Email Samples (Hold Ctrl/Shift for Multi-Select)",
            filetypes=[("Email Files", "*.eml *.txt"), ("All Files", "*.*")]
        )
        if file_paths:
            self.analyze_batch(list(file_paths))

    def scan_single_file(self, file_path: str):
        """Worker function for concurrent thread processing."""
        parsed = parse_email(file_path)
        if not parsed:
            return None

        whitelisted = is_sender_whitelisted(parsed)
        indicators = []
        if not whitelisted:
            indicators.extend(scan_keywords(parsed))
            indicators.extend(scan_urls(parsed))
            indicators.extend(scan_sender(parsed))
            indicators.extend(scan_attachments(parsed))
            indicators.extend(scan_headers(parsed))

        risk_result = calculate_risk(indicators, whitelisted=whitelisted)
        return file_path, parsed, risk_result

    def analyze_batch(self, file_paths: list[str]):
        """Executes multi-threaded concurrent scanning across all selected email files."""
        try:
            with ThreadPoolExecutor() as executor:
                scanned = list(executor.map(self.scan_single_file, file_paths))

            results = [item for item in scanned if item is not None]

            if not results:
                messagebox.showerror("Error", "Failed to parse any of the selected email files.")
                return

            self.batch_results = results
            self.update_selector_dropdown()
            self.load_email_index(0)

            if len(results) > 1:
                messagebox.showinfo(
                    "Batch Processing Complete",
                    f"Successfully scanned {len(results)} email files concurrently!\nUse the dropdown menu to inspect each result."
                )

        except Exception as e:
            messagebox.showerror("Batch Scan Error", f"Failed to complete batch analysis:\n{str(e)}")

    def update_selector_dropdown(self):
        """Refreshes the Combobox options with updated threat levels and filenames."""
        options = []
        for file_path, _, risk_result in self.batch_results:
            lvl_str = risk_result.level.name if hasattr(risk_result.level, "name") else str(risk_result.level)
            options.append(f"[{lvl_str}] {os.path.basename(file_path)}")

        self.file_selector["values"] = options
        self.batch_count_lbl.config(text=f"{len(self.batch_results)} email(s) loaded")

    def on_email_selected(self, event=None):
        """Handles user selecting a different email from the batch dropdown."""
        index = self.file_selector.current()
        if 0 <= index < len(self.batch_results):
            self.load_email_index(index)

    def load_email_index(self, index: int):
        """Loads a specific batch result into the active GUI display."""
        if 0 <= index < len(self.batch_results):
            self.current_index = index
            self.file_selector.current(index)
            self.current_file_path, self.parsed_email, self.risk_result = self.batch_results[index]
            self.update_gui_displays()

    def update_gui_displays(self):
        """Updates UI labels and text boxes with parsed analysis details."""
        if not self.parsed_email or not self.risk_result:
            return

        self.sender_lbl.config(text=f"Sender: {self.parsed_email.sender}")
        self.reply_lbl.config(text=f"Reply-To: {self.parsed_email.headers.get('Reply-To', 'None')}")
        self.subject_lbl.config(text=f"Subject: {self.parsed_email.subject}")

        # Attachments Display
        self.attachments_text.delete("1.0", tk.END)
        if self.parsed_email.attachments:
            for attachment in self.parsed_email.attachments:
                self.attachments_text.insert(tk.END, f"📎 {attachment}\n")
        else:
            self.attachments_text.insert(tk.END, "No attachments detected.")

        # Extracted Links
        self.links_text.delete("1.0", tk.END)
        if self.parsed_email.links:
            for anchor, href in self.parsed_email.links:
                self.links_text.insert(tk.END, f"[{anchor}] -> {href}\n")
        else:
            self.links_text.insert(tk.END, "No links found inside the message.")

        # Risk Score Widget coloring & text
        lvl_str = str(self.risk_result.level.name if hasattr(self.risk_result.level, "name") else self.risk_result.level).split(".")[-1]
        score_text = f"SCORE: {self.risk_result.score:02d} - {lvl_str}"
        if "HIGH" in lvl_str:
            self.score_val_lbl.config(text=score_text, fg="#f3ba88")
        elif "MEDIUM" in lvl_str:
            self.score_val_lbl.config(text=score_text, fg="#fab387")
        else:
            self.score_val_lbl.config(text=score_text, fg="#a6e3a1")

        # Indicators List
        self.indicators_text.delete("1.0", tk.END)
        if self.risk_result.indicators:
            for ind in self.risk_result.indicators:
                clean_name = ind.name.replace("KEYWORD_", "").replace("_", " ").title()
                self.indicators_text.insert(tk.END, f"[+{ind.points} pts] {clean_name}:\n  -> {ind.description}\n\n")
        else:
            self.indicators_text.insert(tk.END, "No suspicious technical markers triggered.")

    def reset_display(self):
        """Resets active email view or removes deleted item from batch."""
        if 0 <= self.current_index < len(self.batch_results):
            del self.batch_results[self.current_index]

        if self.batch_results:
            self.update_selector_dropdown()
            next_idx = min(self.current_index, len(self.batch_results) - 1)
            self.load_email_index(next_idx)
        else:
            self.current_index = -1
            self.current_file_path = None
            self.parsed_email = None
            self.risk_result = None

            self.file_selector["values"] = []
            self.file_selector.set("")
            self.batch_count_lbl.config(text="0 files loaded")

            self.sender_lbl.config(text="Sender: --")
            self.reply_lbl.config(text="Reply-To: --")
            self.subject_lbl.config(text="Subject: --")

            self.attachments_text.delete("1.0", tk.END)
            self.attachments_text.insert(tk.END, "No attachments detected.")

            self.links_text.delete("1.0", tk.END)
            self.links_text.insert(tk.END, "No links found inside the message.")

            self.score_val_lbl.config(text="SCORE: 00 - UNDETERMINED", fg="#fab387")

            self.indicators_text.delete("1.0", tk.END)
            self.indicators_text.insert(tk.END, "No suspicious technical markers triggered.")

    def action_delete(self):
        if not self.parsed_email or not self.current_file_path:
            messagebox.showwarning("No Email", "Please load an email file first!")
            return

        confirm = messagebox.askyesno(
            "Confirm Delete & Block",
            "Are you sure you want to PERMANENTLY delete this email file and blacklist the sender's domain?"
        )
        if confirm:
            try:
                sender_text = str(self.parsed_email.sender).strip()
                domain = None

                if sender_text and sender_text.lower() != "unknown sender":
                    email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_text)
                    if email_match:
                        domain = email_match.group(1).lower()
                    elif "@" in sender_text:
                        domain = sender_text.split("@")[-1].strip("> ").lower()

                if domain:
                    existing = []
                    if os.path.exists("blacklist.txt"):
                        with open("blacklist.txt", "r", encoding="utf-8") as f:
                            existing = [line.strip().lower() for line in f if line.strip()]

                    if domain not in existing:
                        with open("blacklist.txt", "a", encoding="utf-8") as f:
                            f.write(f"\n{domain}")

                file_name = os.path.basename(self.current_file_path)
                if os.path.exists(self.current_file_path):
                    os.remove(self.current_file_path)

                msg = f"File '{file_name}' has been deleted!\nSender domain '{domain}' added to 'blacklist.txt'." if domain else f"File '{file_name}' has been deleted!\nNo valid domain found."
                messagebox.showinfo("Action Executed", msg)
                self.reset_display()

            except Exception as e:
                messagebox.showerror("Error", f"Could not complete action:\n{str(e)}")

    def action_keep(self):
        if not self.parsed_email:
            return
        self.reset_display()

    def action_whitelist(self):
        if not self.parsed_email:
            messagebox.showwarning("No Email", "Please load an email file first!")
            return

        sender_text = str(self.parsed_email.sender).strip()
        domain = None

        if sender_text and sender_text.lower() != "unknown sender":
            email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender_text)
            if email_match:
                domain = email_match.group(1).lower()
            elif "@" in sender_text:
                domain = sender_text.split("@")[-1].strip("> ").lower()

        if not domain:
            messagebox.showwarning(
                "Cannot Whitelist",
                f"Cannot whitelist domain because sender is '{sender_text}'.\nPlease load an email file with a valid 'From:' address."
            )
            return

        try:
            existing = []
            if os.path.exists("whitelist.txt"):
                with open("whitelist.txt", "r", encoding="utf-8") as f:
                    existing = [line.strip().lower() for line in f if line.strip()]

            if domain not in existing:
                with open("whitelist.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n{domain}")
                messagebox.showinfo("Sender Whitelisted", f"Domain '{domain}' added to 'whitelist.txt'!\n\nRe-analyzing batch...")
            else:
                messagebox.showinfo("Already Whitelisted", f"Domain '{domain}' is already whitelisted.\n\nRe-analyzing batch...")

            # Re-scan the active batch
            active_files = [res[0] for res in self.batch_results]
            self.analyze_batch(active_files)

        except Exception as e:
            messagebox.showerror("Error", f"Could not write to whitelist:\n{str(e)}")

    def save_report_dialog(self):
        if not self.parsed_email or not self.risk_result:
            messagebox.showwarning("No Data", "Please scan an email before saving a report.")
            return

        file_name = os.path.basename(self.current_file_path) if self.current_file_path else "email_analysis"

        try:
            saved_path = save_report_to_file(self.parsed_email, self.risk_result, file_name)
            messagebox.showinfo("Saved", f"Analysis report successfully saved to:\n{saved_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()