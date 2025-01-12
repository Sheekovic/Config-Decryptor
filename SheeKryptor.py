import hashlib
import os
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import Tk, Canvas, Label, Entry, Button, filedialog, messagebox, ttk
from ttkthemes import ThemedTk
from cryptography.hazmat.backends import default_backend
import tkinter.font as tkFont

# Define output directory
encrypted_output_directory = "encrypted_files"
decrypted_output_directory = "decrypted_files"

# Function to generate a strong password
def generate_password(length):
    if length < 8:
        messagebox.showwarning("Warning", "Password length should be at least 8 characters.")
        return None

    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Function to update the password entry with the generated password
def create_password():
    try:
        length = int(password_length_entry.get())
        password = generate_password(length)
        if password:
            password_entry.delete(0, 'end')
            password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for password length.")

# Function to generate a personalized password
def generate_personalized_password():
    name = name_entry.get().strip()
    dob = dob_entry.get().strip()
    try:
        length = int(personal_password_length_entry.get())
        if length < 8:
            messagebox.showwarning("Warning", "Password length should be at least 8 characters.")
            return

        if not name or not dob:
            messagebox.showwarning("Warning", "Please provide both Name and Date of Birth.")
            return

        # Combine Name, Date of Birth and Password Length to create a personalized seed
        personalized_seed = name + dob + str(length)
        hashed_seed = hashlib.sha256(personalized_seed.encode('utf-8')).hexdigest()

        # Generate a password based on the hashed seed
        password = ''.join(random.choice(hashed_seed) for i in range(length))

        personal_password_entry.delete(0, 'end')
        personal_password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for password length.")



# Function to generate a key from a password using PBKDF2
def derive_key(password, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(input_file, output_file, password):
    try:
        # Generate a random IV for encryption
        iv = os.urandom(16)  # AES block size is 16 bytes
        salt = os.urandom(16)  # Generate a salt for key derivation

        # Derive the encryption key from the password and salt
        key = derive_key(password, salt)

        with open(input_file, 'rb') as f:
            data = f.read()

        # Encrypt the file data using AES (CBC mode)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Write the salt, IV, and encrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(salt)  # Store the salt for later key derivation
            f.write(iv)    # Store the IV
            f.write(encrypted_data)

        messagebox.showinfo("Success", f"Encryption completed. Output saved to:\n{output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt file: {e}")

# Function to decrypt a file
def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            # Read the salt, IV, and encrypted data
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()

        # Derive the decryption key from the password and salt
        key = derive_key(password, salt)

        # Decrypt the data using AES (CBC mode)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"Decryption completed. Output saved to:\n{output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")

# Function to browse input file
def browse_input_file_decrypt():
    file_path = filedialog.askopenfilename(title="Select File")    
    if file_path:
        decryptor_input_file_entry.delete(0, "end")  # Clear the entry
        decryptor_input_file_entry.insert(0, file_path)  # Insert the selected file path
    else:
        messagebox.showwarning("Warning", "No file selected.")

def browse_input_file_encrypt():
    file_path = filedialog.askopenfilename(title="Select File")    
    if file_path:
        encryptor_input_file_entry.delete(0, "end")  # Clear the entry
        encryptor_input_file_entry.insert(0, file_path)  # Insert the selected file path
    else:
        messagebox.showwarning("Warning", "No file selected.")

# Function to generate output file path with 'encrypted' or 'decrypted' appended
def get_output_file_path(input_file, is_encryption=True):
    base_name = os.path.basename(input_file)
    name, ext = os.path.splitext(base_name)
    
    # If it's encryption, append 'encrypted' to the filename
    if is_encryption:
        new_name = f"{name}_encrypted{ext}"
    else:
        new_name = f"{name}_decrypted{ext}"

    # Ensure the output directory exists
    if not os.path.exists(encrypted_output_directory):
        os.makedirs(encrypted_output_directory)

    return os.path.join(encrypted_output_directory, new_name)

# Function to start encryption
def start_encryption():
    input_file = encryptor_input_file_entry.get()
    password = password_entry.get()

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    output_file = get_output_file_path(input_file, is_encryption=True)
    encrypt_file(input_file, output_file, password)

# Function to start decryption
def start_decryption():
    input_file = decryptor_input_file_entry.get()
    password = decryptor_password_entry.get()

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    output_file = get_output_file_path(input_file, is_encryption=False)
    decrypt_file(input_file, output_file, password)

# Function to change the theme
def change_theme():
    selected_theme = theme_combobox.get()
    style.theme_use(selected_theme)
    style.configure("TLabel", font=(fontStyle, fontSize))
    style.configure("TButton", font=(fontStyle, fontSize))
    style.configure("TEntry", font=(fontStyle, fontSize))
    style.configure("TFrame", font=(fontStyle, fontSize))
    style.configure("TCombobox", font=(fontStyle, fontSize))
    style.configure("TNotebook", font=(fontStyle, fontSize))
    root.update()

# change font size function
def font_options():
    selected_font_size = font_size_combobox.get()
    selected_font_style = font_style_combobox.get()
    style.configure("TNotebook", font=(selected_font_style, selected_font_size))
    style.configure('TEntry', font=(selected_font_style, selected_font_size))
    style.configure('TCombobox', font=(selected_font_style, selected_font_size))
    style.configure('TButton', font=(selected_font_style, selected_font_size))
    style.configure('TLabel', font=(selected_font_style, selected_font_size))
    style.configure('TFrame', font=(selected_font_style, selected_font_size))

def about_sheekryptor():
    messagebox.showinfo("About SheeKryptor", "SheeKryptor is a secure encryption and decryption tool.\n\nVersion: v1.0.0\n\nAuthor: Ahmeed Sheeko\n\nContact: sheekovic@gmail.com")

# Main GUI
version = "v2.0.0"
root = ThemedTk(theme='equilux')
root.title("SheeKryptor " + version)

# Constants
fontStyle = "OCR A Extended"
fontSize = 16
headerFontSize = fontSize + 10


# Colors
black = "#000000"
white = "#FFFFFF"
green = "#00FF00"
red = "#FF0000"

# Create the style object before creating tabs
style = ttk.Style()

# Defult Style Configuration
style.configure("TNotebook", background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TEntry', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TCombobox', font=(fontStyle, fontSize))
style.map('TCombobox', fieldbackground=[('readonly', black)], foreground=[('readonly', green)])
style.configure('TButton', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TLabel', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TFrame', background=black, foreground=green, font=(fontStyle, fontSize))

# Create Tabs for Decryptor and Encryptor
tab_control = ttk.Notebook(root, style="TNotebook")

# Decryptor tab
decryptor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(decryptor_tab, text="Decryptor", padding=10)

# Encryptor tab
encryptor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(encryptor_tab, text="Encryptor", padding=10)

# PWD Generator tab
pwd_generator_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(pwd_generator_tab, text="PWD Generator", padding=10)

# Settings tab
settings_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(settings_tab, text="Settings", padding=10)

# About tab
about_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(about_tab, text="About", padding=10)

# Center the tabs in the window
tab_control.grid(row=0, column=0)

"""
#################### Decryptor Tab ####################
This tab provides the interface for decrypting files. 
Users can input the file to decrypt, provide the password, and initiate the decryption process.
The layout ensures all widgets are centered and evenly spaced.
"""

# Decryptor Tab Input Fields and Buttons
decryptor_label = ttk.Label(decryptor_tab, text="Decryptor", style="TLabel", font=(fontStyle, headerFontSize, "bold"))
decryptor_label.grid(row=0, column=0, columnspan=3, pady=10)

# Description for decryptor tool
decryptor_description = ttk.Label(
    decryptor_tab,
    text=(
        "Use this tool to decrypt files. Select the file, enter the correct password, "
        "and click the 'Decrypt' button to retrieve the original content."
    ),
    style="TLabel",
    wraplength=600,  # Ensure the text wraps for readability
    justify="center",
)
decryptor_description.grid(row=1, column=0, columnspan=3, padx=20, pady=10)

ttk.Label(decryptor_tab, text="Input File:", style="TLabel").grid(row=2, column=0, padx=10, pady=10, sticky="e")

ttk.Button(decryptor_tab, text="Browse", command=browse_input_file_decrypt, style="TButton").grid(row=2, column=2, padx=10, pady=10)

# Ensure we are not using a custom style for the input field and check behavior without it
decryptor_input_file_entry = ttk.Entry(decryptor_tab, width=70, style="TEntry")
decryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

ttk.Label(decryptor_tab, text="Password:", style="TLabel").grid(row=3, column=0, padx=10, pady=10, sticky="e")
decryptor_password_entry = ttk.Entry(decryptor_tab, width=70, style="TEntry")
decryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(decryptor_tab, text="Decrypt", command=start_decryption, style="TButton").grid(row=4, column=0, columnspan=3, pady=20)

#################### Encryptor Tab ####################

# Encryptor Tab Title
ttk.Label(encryptor_tab, text="Encryptor", style="TLabel", font=(fontStyle, headerFontSize, "bold")).grid(row=0, column=0, columnspan=3, pady=20)

# Description for the Encryptor tool
ttk.Label(
    encryptor_tab,
    text=(
        "The Encryptor tool allows you to securely encrypt files with a password. "
        "Select the file you wish to encrypt, enter a strong password, and click 'Encrypt' "
        "to generate an encrypted file."
    ),
    wraplength=600,  # Adjust width for better readability
    style="TLabel"
).grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Encryptor Tab Input Fields and Buttons
ttk.Label(encryptor_tab, text="Input File:", style="TLabel").grid(row=2, column=0, padx=10, pady=10, sticky="e")
encryptor_input_file_entry = ttk.Entry(encryptor_tab, width=70, style="TEntry")
encryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
ttk.Button(encryptor_tab, text="Browse", command=browse_input_file_encrypt, style="TButton").grid(row=2, column=2, padx=10, pady=10)

ttk.Label(encryptor_tab, text="Password:", style="TLabel").grid(row=3, column=0, padx=10, pady=10, sticky="e")
encryptor_password_entry = ttk.Entry(encryptor_tab, width=70, style="TEntry")
encryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(encryptor_tab, text="Encrypt", command=start_encryption, style="TButton").grid(row=4, column=0, columnspan=3, pady=20)

#################### PWD Generator Tab ####################
pwd_generator_tab.grid_columnconfigure(0, weight=1)
pwd_generator_tab.grid_columnconfigure(1, weight=1)

for i in range(10):  # Add weights for all rows
    pwd_generator_tab.grid_rowconfigure(i, weight=1)

# Strong Password Generator Section
ttk.Label(pwd_generator_tab, text="Strong Password Generator", style="TLabel", font=(fontStyle, headerFontSize, "bold")).grid(row=0, column=0, columnspan=2, pady=20)

# Description for the Strong Password Generator tool
ttk.Label(
    pwd_generator_tab,
    text=(
        "The Strong Password Generator helps you create secure passwords of a specified length. "
        "Simply enter the desired password length and click 'Generate Password' to produce a random, "
        "strong password."
    ),
    wraplength=600,  # Adjust width for readability
    style="TLabel"
).grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# Password length input field
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(row=2, column=0, padx=10, pady=10, sticky="e")
password_length_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
password_length_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Button to generate password
ttk.Button(pwd_generator_tab, text="Generate Password", command=create_password, style="TButton").grid(row=3, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(row=4, column=0, padx=10, pady=10, sticky="e")
password_entry = ttk.Entry(pwd_generator_tab, width=40, style="TEntry")
password_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Personalized Password Generator Section
ttk.Label(pwd_generator_tab, text="Personalized Password Generator", style="TLabel", font=(fontStyle, headerFontSize, "bold")).grid(row=5, column=0, columnspan=2, pady=20)

# Description for the Personalized Password Generator tool
ttk.Label(
    pwd_generator_tab,
    text=(
        "The Personalized Password Generator creates passwords based on user-specific details such as "
        "name, date of birth, and preferred password length. This can help generate memorable yet secure passwords."
    ),
    wraplength=600,  # Adjust width for readability
    style="TLabel"
).grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Name input field
ttk.Label(pwd_generator_tab, text="Name:", style="TLabel").grid(row=7, column=0, padx=10, pady=10, sticky="e")
name_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
name_entry.grid(row=7, column=1, padx=10, pady=10, sticky="w")

# Date of Birth input field
ttk.Label(pwd_generator_tab, text="Date of Birth:", style="TLabel").grid(row=8, column=0, padx=10, pady=10, sticky="e")
dob_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
dob_entry.grid(row=8, column=1, padx=10, pady=10, sticky="w")

# Password Length input field
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(row=9, column=0, padx=10, pady=10, sticky="e")
personal_password_length_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
personal_password_length_entry.grid(row=9, column=1, padx=10, pady=10, sticky="w")

# Button to generate personalized password
ttk.Button(pwd_generator_tab, text="Generate Password", command=generate_personalized_password, style="TButton").grid(row=10, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(row=11, column=0, padx=10, pady=10, sticky="e")
personal_password_entry = ttk.Entry(pwd_generator_tab, width=40, style="TEntry")
personal_password_entry.grid(row=11, column=1, padx=10, pady=10, sticky="w")

#################### Settings Tab ####################

settings_tab.grid_columnconfigure(0, weight=1)
for i in range(9):  # Ensure all rows align uniformly
    settings_tab.grid_rowconfigure(i, weight=1)

# Settings Tab Title
ttk.Label(settings_tab, text="Settings", style="TLabel", font=(fontStyle, headerFontSize, "bold")).grid(row=0, column=0, columnspan=2, pady=20)

# Title Label
ttk.Label(settings_tab, text="Theme Control", style="TLabel").grid(row=1, column=0, pady=20)

# List available themes in the combobox
available_themes = root.get_themes()
theme_combobox = ttk.Combobox(
    settings_tab, values=available_themes, style="TCombobox", state="readonly", justify="center"
)
theme_combobox.set(style.theme_use())  # Set the current theme as default
theme_combobox.grid(row=2, column=0, padx=10, pady=10)

# Button to apply theme
apply_theme_button = ttk.Button(settings_tab, text="Apply Theme", command=change_theme, style="TButton")
apply_theme_button.grid(row=3, column=0, padx=10, pady=10)

# Label for font style
ttk.Label(settings_tab, text="Change Font Style", style="TLabel").grid(
    row=4, column=0, pady=20)

# List available font styles in the combobox
available_font_styles = sorted(tkFont.families())  # Get and sort available font families
font_style_combobox = ttk.Combobox(
    settings_tab, values=available_font_styles, style="TCombobox", state="readonly", justify="center"
)
font_style_combobox.set(fontStyle)  # Set the current font style as default
font_style_combobox.grid(row=6, column=0, padx=10, pady=10)

# Label for font size
ttk.Label(settings_tab, text="Change Font Size", style="TLabel").grid(
    row=7, column=0, pady=20)


# List available font sizes in the combobox
available_font_sizes = [8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
font_size_combobox = ttk.Combobox(
    settings_tab, values=available_font_sizes, style="TCombobox", state="readonly", justify="center"
)
font_size_combobox.set(fontSize)  # Set the current font size as default
font_size_combobox.grid(row=9, column=0, padx=10, pady=10)

# Button to apply font options
apply_font_size_button = ttk.Button(settings_tab, text="Apply Font Options", command=font_options, style="TButton")
apply_font_size_button.grid(row=10, column=0, padx=10, pady=10)

# Exit Button
ttk.Label(
    settings_tab,
    text="To close the application",
    wraplength=600,  # Adjust for better readability
    style="TLabel"
).grid(row=11, column=0, padx=10, pady=10)

exit_button = ttk.Button(settings_tab, text="Exit", command=root.destroy, style="TButton")
exit_button.grid(row=12, column=0, padx=10, pady=10)



#################### About Tab ####################

about_tab.grid_columnconfigure(0, weight=1)
about_tab.grid_columnconfigure(1, weight=1)

for i in range(4):  # Add weights for all rows
    about_tab.grid_rowconfigure(i, weight=1)


# SheeKryptor
ttk.Label(about_tab, text="SheeKryptor", style="TLabel", font=(fontStyle, headerFontSize, "bold")).grid(row=0, column=0, columnspan=2, pady=20)

# App Description
app_description = (
    "is a powerful and user-friendly tool for file encryption and decryption and MORE.\n"
    "With an intuitive interface and robust functionality, it ensures your data remains secure."
)
ttk.Label(about_tab, text=app_description, wraplength=600, anchor="center", justify="center", style="TLabel").grid(
    row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

# Version and Features
version_info = (
    "Version: v1.0.0\n"
    "Features:\n"
    "- Secure File Encryption & Decryption\n"
    "- Strong Password Generator\n"
    "- Support for Multiple Themes\n"
    "- Intuitive User Interface\n"
)
ttk.Label(about_tab, text=version_info, anchor="center", justify="center", style="TLabel").grid(
    row=2, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

# Credits
credits = (
    "Developed by: Sheekovic\n"
    "GitHub: @Sheekovic\n"
    "Facebook: /Sheekovic\n"
    "\nThank you for using SheeKryptor!"
)
ttk.Label(about_tab, text=credits, anchor="center", justify="center", style="TLabel").grid(
    row=3, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

root.mainloop()
