# ENTRY POINT TO APPLICATION
# This runs the GUI version of the application. For arguments there are 3 options:
#       1. --gui OR -g: launches the GUI directly
#       2. no argument: also launches the GUI
#       3. <user_input>: treats the argument as file path to an email

#   ----- CODING REQUIREMENTS MET ----- 
#       as most are listed in file gui.py I won't focus on them.
#           The only remaining requirement not used there is:
#   1.MODULE - uses SYS module for command line arguments

# app.py --> either add the email file in the command line or it'll pop up the gui
import sys
import tkinter as tk
from main import run_analysis
from gui import PhishGuardGUI

def launch_gui():
    """Launches the Tkinter Graphical User Interface."""
    print("[System] Launching PhishGuard Graphical User Interface...")
    root = tk.Tk()
    app = PhishGuardGUI(root)       # creates an instance of class PhishGuardGUI that handles the creation of the app interface
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