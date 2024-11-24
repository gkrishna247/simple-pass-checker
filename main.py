import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import os

# Constants for password strength
WEAK = 0
MODERATE = 1
STRONG = 2

def check_password_strength(password):
    """Calculates password strength and provides feedback criteria."""
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
        return WEAK, criteria
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

def animate_progress(value, target):
    """Animates the progress bar."""
    if value < target:
        value += 1
        progress_bar['value'] = value
        app.after(10, animate_progress, value, target)

def update_progress_bar(event=None):
    """Updates UI elements based on password strength."""
    password = entry.get()
    common_passwords = load_common_passwords()

    if password in common_passwords:
        strength = WEAK
        criteria = {}
    else:
        strength, criteria = check_password_strength(password)

    if strength == WEAK:
        target = 33
        strength_label.config(text="Weak", foreground="red")
        progress_bar['style'] = 'Weak.Horizontal.TProgressbar'
    elif strength == MODERATE:
        target = 66
        strength_label.config(text="Moderate", foreground="orange")
        progress_bar['style'] = 'Moderate.Horizontal.TProgressbar'
    else:
        target = 100
        strength_label.config(text="Strong", foreground="green")
        progress_bar['style'] = 'Strong.Horizontal.TProgressbar'

    animate_progress(progress_bar['value'], target)

    for label, met in criteria.items():
        criteria_labels[label].config(fg="green" if met else "red")

def check_password():
    """Provides detailed password strength feedback."""
    password = entry.get()
    common_passwords = load_common_passwords()

    if password in common_passwords:
        messagebox.showwarning("Password Strength", "Weak: This is a common password. Choose a different one.")
        return

    strength, criteria = check_password_strength(password)
    update_progress_bar()

    if strength == STRONG:
        messagebox.showinfo("Password Strength", "Strong: Your password is strong.")
        return

    feedback = "Your password is weak." if strength == WEAK else "Your password is moderate."
    feedback += " Here's how to improve it:\n\n"

    for label, met in criteria.items():
        if not met:
            feedback += f"- {criteria_messages[label]}\n"

    messagebox.showinfo("Password Strength", feedback)

def create_criteria_labels(parent):
    global criteria_labels, criteria_messages
    criteria_labels = {}
    criteria_messages = {
        "length": "At least 8 characters",
        "lowercase": "Include lowercase letters",
        "uppercase": "Include uppercase letters",
        "digit": "Include numbers",
        "special": "Include special characters (!@#$%^&*...)",
        "extended_length": "Ideally 12+ characters",
        "alphanumeric": "Mix letters and numbers",
    }

    for label_text in criteria_messages:
        label = tk.Label(parent, text=criteria_messages[label_text], fg="red", font=("Comic Sans MS", 12))
        label.pack(anchor="w")
        criteria_labels[label_text] = label

def create_header_frame(parent):
    global header_text
    header_frame = tk.Frame(parent, bg="#4CAF50")
    header_frame.pack(side="top", fill="x")

    # Load the logo image for the header
    try:
        logo_image = Image.open("logo.png")
    except FileNotFoundError:
        logo_image = None

    if logo_image:
        logo_image = logo_image.resize((80, 80), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg="#4CAF50")
        logo_label.image = logo_photo
        logo_label.pack(side="left", padx=20, pady=10)

    header_text = tk.Label(
        header_frame,
        text="Password Strength Checker",
        font=("Algerian", 26, "bold"),
        bg="#4CAF50",
        fg="white",
    )
    header_text.pack(side="left", pady=20)

def adjust_title_font(event):
    new_size = max(16, int(event.width / 20))
    header_text.config(font=("Algerian", new_size, "bold"))

def toggle_password_visibility():
    if entry.cget('show') == '•':
        entry.config(show='')
        eye_button.config(image=eye_open_image)
    else:
        entry.config(show='•')
        eye_button.config(image=eye_closed_image)

def main():
    global app, entry, progress_bar, strength_label, eye_button, eye_open_image, eye_closed_image

    app = tk.Tk()
    app.title("🔒 Password Strength Checker 🔑")
    app.geometry("600x650")
    app.configure(bg="#f7f7f7")

    app.style = ttk.Style()
    app.style.theme_use("clam")
    app.style.configure("TLabel", font=("Comic Sans MS", 12), background="#f7f7f7")
    app.style.configure("TButton", font=("Comic Sans MS", 12, "bold"), padding=5)
    app.style.configure("TEntry", font=("Comic Sans MS", 12), padding=5)

    create_header_frame(app)

    content_frame = tk.Frame(app, bg="#f7f7f7")
    content_frame.pack(pady=20, padx=20, fill="both", expand=True)

    ttk.Label(content_frame, text="Enter your password:", style="TLabel").pack(pady=(10, 5))

    entry_frame = tk.Frame(content_frame, bg="#f7f7f7")
    entry_frame.pack(pady=5)

    entry = ttk.Entry(entry_frame, show="•", style="TEntry", width=30)
    entry.pack(side="left")

    eye_open_image = ImageTk.PhotoImage(Image.open("eye_open.png").resize((20, 20), Image.LANCZOS))
    eye_closed_image = ImageTk.PhotoImage(Image.open("eye_closed.png").resize((20, 20), Image.LANCZOS))

    eye_button = tk.Button(entry_frame, image=eye_closed_image, command=toggle_password_visibility, bg="#f7f7f7", bd=0)
    eye_button.pack(side="left", padx=5)

    entry.bind("<KeyRelease>", update_progress_bar)

    ttk.Button(content_frame, text="Check Password", command=check_password, style="TButton").pack(pady=20)

    progress_bar = ttk.Progressbar(content_frame, length=300, mode="determinate", maximum=100, value=0)
    progress_bar.pack(pady=10)

    strength_label = tk.Label(content_frame, text="", font=("Comic Sans MS", 14, "bold"), bg="#f7f7f7")
    strength_label.pack(pady=10)

    criteria_frame = tk.Frame(content_frame, bg="#f7f7f7")
    criteria_frame.pack()
    create_criteria_labels(criteria_frame)

    style = ttk.Style()
    style.configure("Weak.Horizontal.TProgressbar", foreground="red", background="red")
    style.configure("Moderate.Horizontal.TProgressbar", foreground="orange", background="orange")
    style.configure("Strong.Horizontal.TProgressbar", foreground="green", background="green")

    app.bind("<Configure>", adjust_title_font)

    app.mainloop()

if __name__ == "__main__":
    main()
