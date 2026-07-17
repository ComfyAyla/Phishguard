# app.py --> either add the email file in the command line or it'll pop up the gui
import sys
import tkinter as tk
from main import run_analysis
from gui import PhishGuardGUI

def launch_gui():
    """Launches the Tkinter Graphical User Interface."""
    print("[System] Launching PhishGuard Graphical User Interface...")
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()

def main():
    # Check if any command line arguments were provided
    if len(sys.argv) > 1:
        first_arg = sys.argv[1]
        
        # If the user explicitly asks for the GUI using flags
        if first_arg in ["--gui", "-g"]:
            launch_gui()
        else:
            # Otherwise, treat the argument as an email file path for CLI analysis
            run_analysis(first_arg)
    else:
        # Default behavior with no arguments is to launch the GUI
        launch_gui()

if __name__ == "__main__":
    main()