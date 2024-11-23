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
    """Calculates a password strength (WEAK, MODERATE, or STRONG)."""
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search("[a-z]", password):
        strength += 1
    if re.search("[A-Z]", password):
        strength += 1
    if re.search("[0-9]", password):
        strength += 1
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    if len(password) >= 12:
        strength +=1
    if re.search("[a-zA-Z]",password) and re.search("[0-9]",password) :
        strength +=1

    if strength <= 3:
        return WEAK
    elif strength == 4 or strength ==5:
        return MODERATE
    else:
        return STRONG



def load_common_passwords(filename="commonpass.txt"):
    """Loads a list of common passwords from a file."""
    try:
        with open(filename, 'r') as file:
            common_passwords = file.read().splitlines()
        return common_passwords
    except FileNotFoundError:
        messagebox.showerror("Error", f"File {filename} not found.")
        return []

def update_progress_bar(event=None):
    """Updates the progress bar and strength label."""
    password = entry.get()
    common_passwords = load_common_passwords()
    if password in common_passwords:
        strength = WEAK
    else:
        strength = check_password_strength(password)


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

def check_password():
  """Checks password strength and displays a message."""
  update_progress_bar()  # Updates UI elements

  password = entry.get()
  common = load_common_passwords()

  if password in common:
      messagebox.showwarning("Password Strength", "Weak: Your password is too common.")
  else:
      strength = check_password_strength(password)
      if strength == WEAK:
          messagebox.showinfo("Password Strength", "Weak: Your password is weak.")
      elif strength == MODERATE:
          messagebox.showinfo("Password Strength", "Moderate: Your password is moderate.")
      else:
          messagebox.showinfo("Password Strength", "Strong: Your password is strong.")


def main():
    global entry, progress_bar, strength_label #Declare global variables
    
    app = tk.Tk()
    app.title("Password Strength Checker")
    app.geometry("500x450")  # Increased window size
    app.configure(bg="#f2f2f2")  # Light gray background

        # --- Styling ---
    app.style = ttk.Style()
    app.style.theme_use("clam")
    app.style.configure("TLabel", font=("Helvetica", 12), background="#f2f2f2")
    app.style.configure("TButton", font=("Helvetica", 12), padding=10)
    app.style.configure("TEntry", font=("Helvetica", 12), padding=10)

    # --- Header ---
    header_frame = tk.Frame(app, bg="#4CAF50")  # Green header
    header_frame.pack(side="top", fill="x")

    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")  #Correct Path
    try:
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((80, 80), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(header_frame, image=logo_photo, bg="#4CAF50")
        logo_label.image = logo_photo  # Keep a reference
        logo_label.pack(side="left", padx=20, pady=10)
    except FileNotFoundError:
        print(f"Warning: Logo file {logo_path} not found.")


    header_text = tk.Label(header_frame, text="Password Strength Checker", font=("Helvetica", 20, "bold"), bg="#4CAF50", fg="white")
    header_text.pack(side="left", pady=20)

    # --- Content Frame ---
    content_frame = tk.Frame(app, bg="#f2f2f2")
    content_frame.pack(pady=20, padx=30, fill="both", expand=True)

    ttk.Label(content_frame, text="Enter your password:", style="TLabel").pack(pady=(10,5))

    entry = ttk.Entry(content_frame, show="*", style="TEntry", width=30)
    entry.pack(pady=5)
    entry.bind("<KeyRelease>", update_progress_bar)



    ttk.Button(content_frame, text="Check Password", command=check_password, style="TButton").pack(pady=20)

    progress_bar = ttk.Progressbar(content_frame, length=300, mode='determinate', maximum=100)
    progress_bar.pack(pady=10)


    strength_label = tk.Label(content_frame, text="", font=("Helvetica", 14, "bold"), bg="#f2f2f2")
    strength_label.pack(pady=10)



    # Style for the progress bar
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Red.Horizontal.TProgressbar", foreground='red', background='red')
    style.configure("Yellow.Horizontal.TProgressbar", foreground='orange', background='orange')
    style.configure("Green.Horizontal.TProgressbar", foreground='green', background='green')

    app.mainloop()

if __name__ == "__main__":
    main()