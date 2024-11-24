import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import os
import base64

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
        app.after(5, animate_progress, value, target)  # Adjust '5' for speed

def update_progress_bar(event=None):
    """Updates UI elements based on password strength."""
    password = entry.get()
    common_passwords = load_common_passwords()

    if password in common_passwords:
        strength = WEAK
        criteria = {}  # No specific criteria for common passwords
    else:
        strength, criteria = check_password_strength(password)

    if strength == WEAK:
        target = 33
        strength_label.config(text="Weak", foreground="red")
        progress_bar['style'] = 'Red.Horizontal.TProgressbar'
    elif strength == MODERATE:
        target = 66
        strength_label.config(text="Moderate", foreground="orange")
        progress_bar['style'] = 'Yellow.Horizontal.TProgressbar'
    else:
        target = 100
        strength_label.config(text="Strong", foreground="green")
        progress_bar['style'] = 'Green.Horizontal.TProgressbar'

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
    update_progress_bar() # for dynamic UI updates

    if strength == STRONG:
        messagebox.showinfo("Password Strength", "Strong: Your password is strong.")
        return  # Do not give additional feedback if already strong
        

    feedback = ""
    if strength == WEAK:
        feedback = "Your password is weak. Here's how to improve it:\n\n"
    elif strength == MODERATE:
        feedback = "Your password is moderate. Consider these improvements:\n\n"


    for label, met in criteria.items():
        if not met:
            feedback += f"- {criteria_messages[label]}\n"  # criteria_messages are initialized later.


    messagebox.showinfo("Password Strength", feedback)





def create_criteria_labels(parent):
    global criteria_labels, criteria_messages
    criteria_labels = {}  # To hold criteria labels as initialized later
    criteria_messages = { # Provide proper message against respective criteria.
        "length": "At least 8 characters",
        "lowercase": "Include lowercase letters",
        "uppercase": "Include uppercase letters",
        "digit": "Include numbers",
        "special": "Include special characters (!@#$%^&*...)",
        "extended_length": "Ideally 12+ characters",
        "alphanumeric": "Mix letters and numbers"
    }

    for label_text in criteria_messages: # Create labels
        label = tk.Label(parent, text=criteria_messages[label_text], fg="red")  # Initially red
        label.pack(anchor="w") # Place one after one horizontally from West (Left).
        criteria_labels[label_text] = label # Make them globally accessible




def main():
    global app, entry, progress_bar, strength_label


    app = tk.Tk()
    app.title("Password Strength Checker")
    app.geometry("600x550")
    app.configure(bg="#f2f2f2")


    app.style = ttk.Style()
    app.style.theme_use("clam") # clam, alt, default, classic available styles
    app.style.configure("TLabel", font=("Arial", 12), background="#f2f2f2")
    app.style.configure("TButton", font=("Arial", 12), padding=10)
    app.style.configure("TEntry", font=("Arial", 12), padding=10)



    header_frame = tk.Frame(app, bg="#4CAF50")  # Green header
    header_frame.pack(side="top", fill="x")





    try: # Try with direct file name first then with file path
        with open("logo.png", "rb") as f:
            favicon_data = f.read()

    except FileNotFoundError: # try searching the file name logo.png within the current directory
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            logo_path = os.path.join(script_dir, "logo.png")
            with open(logo_path, "rb") as f: #  read as bytes 'rb' for image
                favicon_data = f.read()

        except FileNotFoundError:
            print(f"Warning: Favicon file not found.")
            favicon_data = None


    if favicon_data:  # If icon data was found correctly in any way
        favicon = base64.b64encode(favicon_data).decode("ascii")
        icon_photo = tk.PhotoImage(data=favicon) # generate image data from b64 string
        app.iconphoto(False, icon_photo)




    try:  # Place both icon in header as well in Title.

        logo_image = Image.open("logo.png") # Try current location as 1st preference

    except FileNotFoundError:
        try: # Use File Path (Better Solution to locate correct directory even program files)
            script_dir = os.path.dirname(os.path.abspath(__file__)) # This gives path not just working directory of ide
            logo_path = os.path.join(script_dir, "logo.png") # correct file location regardless from which ide/directory running the code from
            logo_image = Image.open(logo_path) # load with file location
        except FileNotFoundError:
            print(f"Warning: Logo file not found.")
            logo_image = None



    if logo_image:

        logo_image = logo_image.resize((80, 80), Image.LANCZOS) # Set Logo dimension, use High quality resize filter like LANCZOS (Other Options: NEAREST, BOX, BILINEAR, HAMMING, BICUBIC)
        logo_photo = ImageTk.PhotoImage(logo_image)  # Tkinter usable format
        logo_label = tk.Label(header_frame, image=logo_photo, bg="#4CAF50")
        logo_label.image = logo_photo
        logo_label.pack(side="left", padx=20, pady=10)






    header_text = tk.Label(header_frame, text="Password Strength Checker", font=("Arial", 20, "bold"), bg="#4CAF50", fg="white")
    header_text.pack(side="left", pady=20)




    content_frame = tk.Frame(app, bg="#f2f2f2")
    content_frame.pack(pady=20, padx=30, fill="both", expand=True)




    ttk.Label(content_frame, text="Enter your password:", style="TLabel").pack(pady=(10, 5))


    entry = ttk.Entry(content_frame, show="*", style="TEntry", width=30)
    entry.pack(pady=5)

    entry.bind("<KeyRelease>", update_progress_bar)



    ttk.Button(content_frame, text="Check Password", command=check_password, style="TButton").pack(pady=20)



    progress_bar = ttk.Progressbar(content_frame, length=300, mode='determinate', maximum=100, value=0)  # set initial value
    progress_bar.pack(pady=10)




    strength_label = tk.Label(content_frame, text="", font=("Arial", 14, "bold"), bg="#f2f2f2")
    strength_label.pack(pady=10)




    criteria_frame = tk.Frame(content_frame, bg="#f2f2f2")  # for criteria labels
    criteria_frame.pack() # must pack the criteria_frame in content_frame after the password box.
    create_criteria_labels(criteria_frame)



    style = ttk.Style()
    style.theme_use('clam')

    style.configure("Red.Horizontal.TProgressbar", foreground='red', background='red')
    style.configure("Yellow.Horizontal.TProgressbar", foreground='orange', background='orange')
    style.configure("Green.Horizontal.TProgressbar", foreground='green', background='green')


    app.mainloop()


if __name__ == "__main__":
    main()