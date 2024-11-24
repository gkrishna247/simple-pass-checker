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

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Strength Checker 🔑")
        self.root.geometry("600x650")
        self.root.configure(bg="#f7f7f7")

        self.criteria_labels = {}
        self.criteria_messages = {
            "length": "At least 8 characters",
            "lowercase": "Include lowercase letters",
            "uppercase": "Include uppercase letters",
            "digit": "Include numbers",
            "special": "Include special characters (!@#$%^&*...)",
            "extended_length": "Ideally 12+ characters",
            "alphanumeric": "Mix letters and numbers",
        }

        self.setup_ui()

    def setup_ui(self):
        self.add_favicon()
        self.create_header_frame()
        self.create_content_frame()
        self.create_criteria_labels()

        self.root.bind("<Configure>", self.adjust_title_font)
        self.root.mainloop()

    def add_favicon(self):
        try:
            self.root.iconphoto(False, tk.PhotoImage(file="logo.png"))
        except Exception as e:
            print("Favicon not found:", e)

    def create_header_frame(self):
        self.header_frame = tk.Frame(self.root, bg="#4CAF50")
        self.header_frame.pack(side="top", fill="x")

        try:
            logo_image = Image.open("logo.png")
        except FileNotFoundError:
            logo_image = None

        if logo_image:
            logo_image = logo_image.resize((80, 80), Image.LANCZOS)
            logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(self.header_frame, image=logo_photo, bg="#4CAF50")
            logo_label.image = logo_photo
            logo_label.pack(side="left", padx=20, pady=10)

        self.header_text = tk.Label(
            self.header_frame,
            text="Password Strength Checker",
            font=("Algerian", 26, "bold"),
            bg="#4CAF50",
            fg="white",
        )
        self.header_text.pack(side="left", pady=20)

    def create_content_frame(self):
        self.content_frame = tk.Frame(self.root, bg="#f7f7f7")
        self.content_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ttk.Label(self.content_frame, text="Enter your password:", style="TLabel").pack(pady=(10, 5))

        self.entry_frame = tk.Frame(self.content_frame, bg="#f7f7f7")
        self.entry_frame.pack(pady=5)

        self.entry = ttk.Entry(self.entry_frame, show="•", style="TEntry", width=30)
        self.entry.pack(side="left")

        self.eye_open_image = ImageTk.PhotoImage(Image.open("eye_open.png").resize((20, 20), Image.LANCZOS))
        self.eye_closed_image = ImageTk.PhotoImage(Image.open("eye_closed.png").resize((20, 20), Image.LANCZOS))

        self.eye_button = tk.Button(self.entry_frame, image=self.eye_closed_image, command=self.toggle_password_visibility, bg="#f7f7f7", bd=0)
        self.eye_button.pack(side="left", padx=5)

        self.entry.bind("<KeyRelease>", self.update_progress_bar)

        ttk.Button(self.content_frame, text="Check Password", command=self.check_password, style="TButton").pack(pady=20)

        self.progress_bar = ttk.Progressbar(self.content_frame, length=300, mode="determinate", maximum=100, value=0)
        self.progress_bar.pack(pady=10)

        self.strength_label = tk.Label(self.content_frame, text="", font=("Comic Sans MS", 14, "bold"), bg="#f7f7f7")
        self.strength_label.pack(pady=10)

        self.criteria_frame = tk.Frame(self.content_frame, bg="#f7f7f7")
        self.criteria_frame.pack()

        style = ttk.Style()
        style.configure("Weak.Horizontal.TProgressbar", foreground="red", background="red")
        style.configure("Moderate.Horizontal.TProgressbar", foreground="orange", background="orange")
        style.configure("Strong.Horizontal.TProgressbar", foreground="green", background="green")

    def create_criteria_labels(self):
        for label_text in self.criteria_messages:
            label = tk.Label(self.criteria_frame, text=self.criteria_messages[label_text], fg="red", font=("Comic Sans MS", 12))
            label.pack(anchor="w")
            self.criteria_labels[label_text] = label

    def adjust_title_font(self, event):
        new_size = max(25, int(event.width / 20))
        self.header_text.config(font=("Rockwell", new_size, "bold"))

    def toggle_password_visibility(self):
        if self.entry.cget('show') == '•':
            self.entry.config(show='')
            self.eye_button.config(image=self.eye_open_image)
        else:
            self.entry.config(show='•')
            self.eye_button.config(image=self.eye_closed_image)

    def load_common_passwords(self, filename="commonpass.txt"):
        try:
            with open(filename, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError:
            messagebox.showerror("Error", f"File {filename} not found.")
            return []

    def check_password_strength(self, password):
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

    def pulsate_progress_bar(self, start, target, delta=1):
        current = self.progress_bar['value']
        if abs(current - target) < delta:
            self.progress_bar['value'] = target
            return
        if current < target:
            self.progress_bar['value'] += delta
        else:
            self.progress_bar['value'] -= delta
        self.root.after(10, self.pulsate_progress_bar, start, target, delta)

    def update_progress_bar(self, event=None):
        password = self.entry.get()
        common_passwords = self.load_common_passwords()

        if password in common_passwords:
            strength = WEAK
            criteria = {}
        else:
            strength, criteria = self.check_password_strength(password)

        if strength == WEAK:
            target = 33
            self.strength_label.config(text="Weak", foreground="red")
            self.progress_bar['style'] = 'Weak.Horizontal.TProgressbar'
        elif strength == MODERATE:
            target = 66
            self.strength_label.config(text="Moderate", foreground="orange")
            self.progress_bar['style'] = 'Moderate.Horizontal.TProgressbar'
        else:
            target = 100
            self.strength_label.config(text="Strong", foreground="green")
            self.progress_bar['style'] = 'Strong.Horizontal.TProgressbar'

        self.pulsate_progress_bar(self.progress_bar['value'], target)

        for label, met in criteria.items():
            self.criteria_labels[label].config(fg="green" if met else "red")

    def check_password(self):
        password = self.entry.get()
        common_passwords = self.load_common_passwords()

        if password in common_passwords:
            messagebox.showwarning("Password Strength", "Weak: This is a common password. Choose a different one.")
            return

        strength, criteria = self.check_password_strength(password)
        self.update_progress_bar()

        if strength == STRONG:
            messagebox.showinfo("Password Strength", "Strong: Your password is strong.")
            return

        feedback = "Your password is weak." if strength == WEAK else "Your password is moderate."
        feedback += " Here's how to improve it:\n\n"

        for label, met in criteria.items():
            if not met:
                feedback += f"- {self.criteria_messages[label]}\n"

        messagebox.showinfo("Password Strength", feedback)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
