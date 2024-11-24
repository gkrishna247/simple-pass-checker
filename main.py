import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import os

# Constants for clearer code
WEAK = 0
MODERATE = 1
STRONG = 2

def check_password_strength(password):
    """Calculates password strength."""
    strength = 0
    criteria = {
        "length": len(password) >= 8,
        "lowercase": re.search("[a-z]", password),
        "uppercase": re.search("[A-Z]", password),
        "digit": re.search("[0-9]", password),
        "special": re.search("[!@#$%^&*(),.?\":{}|<>]", password),
        "extended_length": len(password) >= 12,
        "alphanumeric": re.search("[a-zA-Z]", password) and re.search("[0-9]", password),
    }

    for value in criteria.values():
        if value:
            strength += 1

    if strength <= 3:
        return WEAK, criteria  # Return criteria for detailed feedback
    elif strength == 4 or strength == 5:
        return MODERATE, criteria
    else:
        return STRONG, criteria

def load_common_passwords(filename="commonpass.txt"):
    """Loads common passwords from a file."""
    try:
        with open(filename, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        messagebox.showerror("Error", f"File {filename} not found.")
        return []


def update_progress_bar(event=None):
    """Updates progress bar, strength label, and criteria labels."""
    password = entry.get()
    common_passwords = load_common_passwords()

    if password in common_passwords:
        strength = WEAK
        criteria = {}  # No specific criteria feedback for common passwords
    else:
        strength, criteria = check_password_strength(password)

    update_ui(strength, criteria)



def update_ui(strength, criteria):
    """Updates all UI elements based on password strength and criteria."""

    if strength == WEAK:
        progress_bar['value'] = 33
        progress_bar['style'] = 'Red.Horizontal.TProgressbar'
        strength_label.config(text="Weak", foreground="red")
    elif strength == MODERATE:
        progress_bar['value'] = 66
        progress_bar['style'] = 'Yellow.Horizontal.TProgressbar'
        strength_label.config(text="Moderate", foreground="orange")
    else:
        progress_bar['value'] = 100
        progress_bar['style'] = 'Green.Horizontal.TProgressbar'
        strength_label.config(text="Strong", foreground="green")

    # Update criteria labels
    for label, met in criteria.items():
        criteria_labels[label].config(fg="green" if met else "red")


def check_password():
    """Checks password strength and displays detailed feedback."""
    password = entry.get()
    common_passwords = load_common_passwords()
    if password in common_passwords:
        messagebox.showwarning("Password Strength", "Weak: This is a very common password. Please choose a different one.")
        return

    strength, criteria = check_password_strength(password)
    update_ui(strength, criteria) # ensure UI update

    feedback = ""
    if strength == WEAK:
        feedback = "Your password is weak. Here's how to improve it:\n\n"
    elif strength == MODERATE:
        feedback = "Your password is moderate. Consider these improvements:\n\n"
    else:

        messagebox.showinfo("Password Strength", "Strong: Your password is strong.")
        return  # Exit early if strong

    for label, met in criteria.items():
        if not met:
            feedback += f"- {criteria_messages[label]}\n"

    messagebox.showinfo("Password Strength", feedback)



def create_criteria_labels(parent):
    global criteria_labels, criteria_messages # make it available throughout
    criteria_labels = {}
    criteria_messages = {
        "length": "At least 8 characters",
        "lowercase": "Include lowercase letters",
        "uppercase": "Include uppercase letters",
        "digit": "Include numbers",
        "special": "Include special characters (!@#$%^&*...)",
        "extended_length": "Ideally 12+ characters",
        "alphanumeric": "Mix letters and numbers"
    }
    for label_text in criteria_messages:

        label = tk.Label(parent, text=criteria_messages[label_text], fg="red") # Initially red
        label.pack(anchor="w")
        criteria_labels[label_text] = label





def main():

    global entry, progress_bar, strength_label
    app = tk.Tk()
    app.title("Password Strength Checker")
    app.geometry("600x550")
    app.configure(bg="#f2f2f2")


    app.style = ttk.Style()
    app.style.theme_use("clam")
    app.style.configure("TLabel", font=("Arial", 12), background="#f2f2f2")
    app.style.configure("TButton", font=("Arial", 12), padding=10)
    app.style.configure("TEntry", font=("Arial", 12), padding=10)


    header_frame = tk.Frame(app, bg="#4CAF50")
    header_frame.pack(side="top", fill="x")


    script_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(script_dir, "logo.png")

    try:
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((80, 80), Image.LANCZOS) # Using high-quality resize filter
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg="#4CAF50")
        logo_label.image = logo_photo
        logo_label.pack(side="left", padx=20, pady=10)
    except FileNotFoundError:
        print(f"Warning: Logo file not found at {logo_path}")


    header_text = tk.Label(header_frame, text="Password Strength Checker", font=("Arial", 20, "bold"), bg="#4CAF50", fg="white")
    header_text.pack(side="left", pady=20)




    content_frame = tk.Frame(app, bg="#f2f2f2")
    content_frame.pack(pady=20, padx=30, fill="both", expand=True)

    ttk.Label(content_frame, text="Enter your password:", style="TLabel").pack(pady=(10, 5))

    entry = ttk.Entry(content_frame, show="*", style="TEntry", width=30)
    entry.pack(pady=5)
    entry.bind("<KeyRelease>", update_progress_bar)

    ttk.Button(content_frame, text="Check Password", command=check_password, style="TButton").pack(pady=20)


    progress_bar = ttk.Progressbar(content_frame, length=300, mode='determinate', maximum=100)
    progress_bar.pack(pady=10)

    strength_label = tk.Label(content_frame, text="", font=("Arial", 14, "bold"), bg="#f2f2f2")
    strength_label.pack(pady=10)

    criteria_frame = tk.Frame(content_frame, bg="#f2f2f2") # dedicated frame for criteria labels
    criteria_frame.pack()
    create_criteria_labels(criteria_frame)



    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Red.Horizontal.TProgressbar", foreground='red', background='red')
    style.configure("Yellow.Horizontal.TProgressbar", foreground='orange', background='orange')
    style.configure("Green.Horizontal.TProgressbar", foreground='green', background='green')


    app.mainloop()

if __name__ == "__main__":
    main()