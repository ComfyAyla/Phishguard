import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Import our working backend logic
from parser import read_email_file, parse_email
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender
from detectors.attachments import scan_attachments
from detectors.headers import scan_headers
from detectors.whitelist import is_sender_whitelisted  # <-- New Import
from scoring import calculate_risk
from report import generate_text_report, save_report_to_file


class PhishGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard - Interactive Email Threat Analyzer")
        self.root.geometry("900x750")
        self.root.configure(bg="#1e1e2e")

        # Track state
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
            text="📁 Browse Email File (.eml / .txt)", 
            command=self.browse_file,
            bg="#89b4fa", fg="#11111b", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.browse_btn.pack(side="right")

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
        self.score_val_lbl = tk.Label(score_card, text="SCORE: 00 - UNDETERMINED", bg="#252538", fg="#fab387", font=("Segoe UI", 14, "bold"))
        self.score_val_lbl.pack(fill="x", pady=5)

        # Triggered Indicators List Card
        indicators_card = ttk.Frame(right_col, style="Card.TFrame", padding=12)
        indicators_card.pack(fill="both", expand=True, pady=5)
        
        ttk.Label(indicators_card, text="SECURITY INDICATORS & POINT BREAKDOWN", style="Sub.TLabel").pack(anchor="w", pady=(0, 5))
        self.indicators_text = tk.Text(indicators_card, bg="#181825", fg="#f38ba8", insertbackground="white", font=("Consolas", 10), height=12, relief="flat")
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

    def browse_file(self):
        """Open a file dialog to locate an email file."""
        file_path = filedialog.askopenfilename(
            title="Open Email Sample",
            filetypes=[("Email Files", "*.eml *.txt"), ("All Files", "*.*")]
        )
        if file_path:
            self.current_file_path = file_path
            self.analyze_email()

    def analyze_email(self):
        """Drives the backend pipeline and displays results in the GUI."""
        try:
            raw_text = read_email_file(self.current_file_path)
            self.parsed_email = parse_email(raw_text)

            # 1. Check if Whitelisted First
            whitelisted = is_sender_whitelisted(self.parsed_email)

            # 2. Run All Active Detectors
            indicators = []
            if not whitelisted:
                indicators.extend(scan_keywords(self.parsed_email))
                indicators.extend(scan_urls(self.parsed_email))
                indicators.extend(scan_sender(self.parsed_email))
                indicators.extend(scan_attachments(self.parsed_email))
                indicators.extend(scan_headers(self.parsed_email))

            # 3. Calculate score
            self.risk_result = calculate_risk(indicators, whitelisted=whitelisted)

            # 4. Populate GUI elements
            self.update_gui_displays()
        except Exception as e:
            messagebox.showerror("Parsing Error", f"Failed to analyze email file:\n{str(e)}")

    def update_gui_displays(self):
        """Updates UI labels and text boxes with parsed analysis details."""
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
            for link in self.parsed_email.links:
                self.links_text.insert(tk.END, f"{link}\n")
        else:
            self.links_text.insert(tk.END, "No links found inside the message.")

        # Risk Score Widget coloring & text
        score_text = f"SCORE: {self.risk_result.score} - {self.risk_result.level}"
        if self.risk_result.level == "HIGH":
            self.score_val_lbl.config(text=score_text, fg="#f38ba8")
        elif self.risk_result.level == "MEDIUM":
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
        """Resets the UI back to empty state."""
        self.current_file_path = None
        self.parsed_email = None
        self.risk_result = None
        
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

    # --- Interactive Button Actions (Fully Functional!) ---
    def action_delete(self):
        if not self.parsed_email or not self.current_file_path:
            messagebox.showwarning("No Email", "Please load an email file first!")
            return
            
        confirm = messagebox.askyesno(
            "Confirm Delete & Block", 
            "Are you sure you want to PERMANENTLY delete this email file and black-list the sender's domain?"
        )
        if confirm:
            try:
                # 1. Block the sender's domain (add to blacklist.txt)
                email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', self.parsed_email.sender)
                if email_match:
                    domain = email_match.group(1).lower()
                    
                    # Read current blacklist to prevent duplicates
                    existing = []
                    if os.path.exists("blacklist.txt"):
                        with open("blacklist.txt", "r", encoding="utf-8") as f:
                            existing = [line.strip().lower() for line in f]
                            
                    if domain not in existing:
                        with open("blacklist.txt", "a", encoding="utf-8") as f:
                            f.write(f"\n{domain}")
                
                # 2. Physically Delete the raw file from disk
                if os.path.exists(self.current_file_path):
                    os.remove(self.current_file_path)
                    
                messagebox.showinfo(
                    "Action Executed", 
                    f"File '{os.path.basename(self.current_file_path)}' has been physically deleted!\n"
                    f"Sender domain '{domain}' has been added to 'blacklist.txt'."
                )
                
                # Reset display to clear deleted data
                self.reset_display()
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not complete action:\n{str(e)}")

    def action_keep(self):
        if not self.parsed_email:
            return
        # Safe reset clears current window data without hurting the source file
        self.reset_display()
        messagebox.showinfo("Cleared", "Active preview cleared. File remains safely stored in your system.")

    def action_whitelist(self):
        if not self.parsed_email:
            messagebox.showwarning("No Email", "Please load an email file first!")
            return
            
        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', self.parsed_email.sender)
        if email_match:
            domain = email_match.group(1).lower()
            try:
                # Read current whitelist to prevent duplicates
                existing = []
                if os.path.exists("whitelist.txt"):
                    with open("whitelist.txt", "r", encoding="utf-8") as f:
                        existing = [line.strip().lower() for line in f]
                        
                if domain not in existing:
                    with open("whitelist.txt", "a", encoding="utf-8") as f:
                        f.write(f"\n{domain}")
                
                messagebox.showinfo(
                    "Sender Whitelisted", 
                    f"Domain '{domain}' is now whitelisted!\n"
                    "Future scans on emails from this sender will register as safe (LOW Risk)."
                )
                
                # Re-run analysis immediately to update GUI to safe state
                self.analyze_email()
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not write to whitelist:\n{str(e)}")

    def save_report_dialog(self):
        if not self.parsed_email or not self.risk_result:
            messagebox.showwarning("No Data", "Please scan an email before saving a report.")
            return

        file_name = os.path.basename(self.current_file_path)
        default_save_name = f"report_{os.path.splitext(file_name)[0]}.txt"

        save_path = filedialog.asksaveasfilename(
            title="Save Full Text Report",
            initialfile=default_save_name,
            filetypes=[("Text Files", "*.txt")]
        )
        if save_path:
            report_text = generate_text_report(self.parsed_email, self.risk_result, file_name)
            save_report_to_file(report_text, save_path)
            messagebox.showinfo("Saved", f"Analysis report successfully saved to:\n{save_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()
