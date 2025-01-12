import hashlib
import json
import os
import random
import sqlite3
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
from ttkthemes import ThemedTk
from cryptography.hazmat.backends import default_backend
import tkinter.font as tkFont
import pyotp
import configparser

# Database Setup
conn = sqlite3.connect("2fa_accounts.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    username TEXT NOT NULL,
    key TEXT NOT NULL,
    time_based INTEGER NOT NULL
)
""")
conn.commit()

    
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

# Function to load settings
def load_settings():
    config = configparser.ConfigParser()
    config.read("settings.ini")
    if "Settings" in config:
        # Apply saved theme
        saved_theme = config["Settings"].get("theme", "equilux")
        if saved_theme in style.theme_names():
            style.theme_use(saved_theme)
        
        # Apply saved font size and style
        saved_font_size = config["Settings"].get("font_size", "16")
        saved_font_style = config["Settings"].get("font_style", "OCR A Extended")
        style.configure("TLabel", font=(saved_font_style, saved_font_size))
        style.configure("TButton", font=(saved_font_style, saved_font_size))
        style.configure("TEntry", font=(saved_font_style, saved_font_size))
        style.configure("TFrame", font=(saved_font_style, saved_font_size))
        style.configure("TCombobox", font=(saved_font_style, saved_font_size))
        style.configure("TNotebook", font=(saved_font_style, saved_font_size))
        style.configure("TCanvas", font=(saved_font_style, saved_font_size))
        style.configure("TCheckbutton", font=(saved_font_style, saved_font_size))
        style.configure("TScrollbar", font=(saved_font_style, saved_font_size))
        style.configure("Treeview", font=(saved_font_style, saved_font_size))
        # Refresh the application
        root.update()

# Function to update settings
def update_settings():
    selected_theme = theme_combobox.get()
    style.theme_use(selected_theme)

    selected_font_size = font_size_combobox.get()
    selected_font_style = font_style_combobox.get()

    style.configure("TLabel", font=(selected_font_style, selected_font_size))
    style.configure("TButton", font=(selected_font_style, selected_font_size))
    style.configure("TEntry", font=(selected_font_style, selected_font_size))
    style.configure("TFrame", font=(selected_font_style, selected_font_size))
    style.configure("TCombobox", font=(selected_font_style, selected_font_size))
    style.configure("TNotebook", font=(selected_font_style, selected_font_size))
    style.configure("TCanvas", font=(selected_font_style, selected_font_size))
    style.configure("TCheckbutton", font=(selected_font_style, selected_font_size))
    style.configure("TScrollbar", font=(selected_font_style, selected_font_size))
    style.configure("Treeview", font=(selected_font_style, selected_font_size))
    
    # Refresh the application
    root.update()

    # Save settings to settings.ini
    config = configparser.ConfigParser()
    config["Settings"] = {
        "theme": selected_theme,
        "font_size": selected_font_size,
        "font_style": selected_font_style
    }
    with open("settings.ini", "w") as f:
        config.write(f)


def send_api_request():
    api_url = api_url_entry.get()
    request_type = request_type_combobox.get()
    headers = headers_entry.get()
    auth_token = auth_token_entry.get()
    request_body = request_body_entry.get()

    headers_dict = {}
    try:
        if headers:
            headers_dict = json.loads(headers)  # Parse headers as JSON if provided
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Invalid headers format. Please provide valid JSON.")

    # Add Authorization token to headers if provided
    if auth_token:
        headers_dict["Authorization"] = f"Bearer {auth_token}"

    try:
        # Send the API request based on the selected type
        if request_type == "GET":
            response = requests.get(api_url, headers=headers_dict)
        elif request_type == "POST":
            response = requests.post(api_url, json=json.loads(request_body), headers=headers_dict)
        elif request_type == "PUT":
            response = requests.put(api_url, json=json.loads(request_body), headers=headers_dict)
        elif request_type == "DELETE":
            response = requests.delete(api_url, headers=headers_dict)

        # Display the response in the response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Response Code: {response.status_code}\n")
        response_text.insert("insert", f"Response Body:\n{response.text}")
    
    except requests.exceptions.RequestException as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Request failed: {e}")
    except json.JSONDecodeError as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Invalid request body format. Please provide valid JSON, {e}")
    except Exception as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Failed to send API request: {e}")

# Optional: Save Results Button (save to a text file)
def save_results():
    try:
        response_data = response_text.get(1.0, "end")
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(response_data)
            messagebox.showinfo("Success", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results: {e}")

# Function to add an account
def add_account():
    provider = provider_entry.get()
    username = username_entry.get()
    key = key_entry.get()
    # Remove spaces from the key
    key = key.replace(" ", "")
    time_based = time_based_var.get()

    if not username or not key:
        messagebox.showerror("Error", "Username and Key are required!")
        return

    try:
        # Validate Key
        otp = pyotp.TOTP(key)
        otp.now()  # Test generation
    except:
        messagebox.showerror("Error", "Invalid 2FA Key!")
        return

    # Generate the custom id: first two letters of provider + first two letters of username
    custom_id = provider[:2].upper() + username[:2].upper()

    # Get the current max number from the table to increment the ID
    cursor.execute("SELECT MAX(SUBSTR(id, 5, LENGTH(id))) FROM accounts WHERE id LIKE ?", (custom_id + '%',))
    max_id_suffix = cursor.fetchone()[0]

    # If no records exist, start from 1
    if max_id_suffix is None:
        id_suffix = 1
    else:
        id_suffix = int(max_id_suffix) + 1

    # Create the final unique ID
    final_id = custom_id + str(id_suffix)

    cursor.execute("INSERT INTO accounts (id, provider, username, key, time_based) VALUES (?, ?, ?, ?, ?)",
                   (final_id, provider, username, key, time_based))
    conn.commit()
    refresh_accounts()
    messagebox.showinfo("Success", "Account added successfully!")
    
# Function to delete account from the database
def delete_account():
    selected_account = account_combobox.get()

    if not selected_account:
        messagebox.showerror("Error", "No account selected for deletion!")
        return

    # Delete the account from the database based on the selected id
    cursor.execute("DELETE FROM accounts WHERE id = ?", (selected_account,))
    conn.commit()
    refresh_accounts()
    messagebox.showinfo("Success", "Account deleted successfully!")

def refresh_accounts():
    # Delete all rows in the table
    for row in accounts_table.get_children():
        accounts_table.delete(row)

    # Fetch accounts from the database, including the id
    cursor.execute("SELECT id, provider, username, key, time_based FROM accounts")
    accounts = cursor.fetchall()  # Store the accounts to use later

    # Insert rows into the table
    for account in accounts:
        otp = pyotp.TOTP(account[3])
        current_otp = otp.now()
        accounts_table.insert("", "end", values=(account[0], account[1], account[2], current_otp))

    # Update the combobox values with account ids
    account_combobox['values'] = [account[0] for account in accounts]


def update_otps():
    for child in accounts_table.get_children():
        item = accounts_table.item(child)
        username = item['values'][0]

        cursor.execute("SELECT key FROM accounts WHERE username = ?", (username,))
        account = cursor.fetchone()
        if account:
            otp = pyotp.TOTP(account[0])
            current_otp = otp.now()
            accounts_table.item(child, values=(username, current_otp))

    root.after(1000, update_otps)  # Refresh OTPs every second
    
def about_sheekryptor():
    messagebox.showinfo("About SheeKryptor", "SheeKryptor is a secure encryption and decryption tool.\n\nVersion: v1.0.0\n\nAuthor: Ahmeed Sheeko\n\nContact: sheekovic@gmail.com")

################## Main GUI ##################

# Main GUI
version = "v2.2.1"
root = ThemedTk(theme='equilux')
root.title("SheeKryptor " + version)
# Set the window icon
root.iconbitmap("assets/SheeKryptor.ico")

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
# Configure the default button style
style.configure('TButton', background="black", foreground="green", font=(fontStyle, fontSize))
# Map the button style for different states (active, pressed, and hover)
style.map('TButton',
          foreground=[('pressed', 'white'),  # Green text when pressed
                      ('active', green)])
style.configure('TLabel', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TFrame', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TCheckbutton', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TCanvas', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TFrame', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('TScrollbar', background=black, foreground=green, font=(fontStyle, fontSize))
style.configure('Treeview', background=black, foreground=green, font=(fontStyle, fontSize))

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

# Add the API Testing Tab to the Notebook
api_testing_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(api_testing_tab, text="API Testing", padding=10)

# Add 2FA Tool Tab to the Notebook
two_factor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(two_factor_tab, text="2FA Tool", padding=10)

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
# Configure columns and rows for alignment
decryptor_tab.grid_columnconfigure(0, weight=1)
decryptor_tab.grid_columnconfigure(1, weight=1)
decryptor_tab.grid_columnconfigure(2, weight=1)
for i in range(6):  # Ensure all rows align uniformly
    decryptor_tab.grid_rowconfigure(i, weight=1)

# Decryptor Tab Input Fields and Buttons
decryptor_label = ttk.Label(decryptor_tab, text="Decryptor", style="TLabel")
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
# Configure columns and rows for alignment
encryptor_tab.grid_columnconfigure(0, weight=1)
encryptor_tab.grid_columnconfigure(1, weight=1)
encryptor_tab.grid_columnconfigure(2, weight=1)
for i in range(6):  # Ensure all rows align uniformly
    encryptor_tab.grid_rowconfigure(i, weight=1)

# Encryptor Tab Title
ttk.Label(encryptor_tab, text="Encryptor", style="TLabel").grid(row=0, column=0, columnspan=3, pady=20)

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
ttk.Label(pwd_generator_tab, text="Strong Password Generator", style="TLabel").grid(row=0, column=0, columnspan=2, pady=20)

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
ttk.Label(pwd_generator_tab, text="Personalized Password Generator", style="TLabel").grid(row=5, column=0, columnspan=2, pady=20)

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

#################### API Test Tab ####################
# Configure columns and rows for centering
api_testing_tab.grid_columnconfigure(0, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    api_testing_tab.grid_rowconfigure(i, weight=1)

# API Testing Tab Title
ttk.Label(api_testing_tab, text="API Testing", style="TLabel").grid(row=0, column=0, columnspan=3, pady=20)

# API URL Entry
ttk.Label(api_testing_tab, text="API URL:", style="TLabel").grid(row=1, column=0, padx=10, pady=10, sticky="w")  # Align label to the right
api_url_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
api_url_entry.grid(row=1, column=1, padx=10, pady=10, sticky="e")

# API Request Type (GET, POST, PUT, DELETE)
ttk.Label(api_testing_tab, text="Request Type:", style="TLabel").grid(row=2, column=0, padx=10, pady=10, sticky="w")
request_type_combobox = ttk.Combobox(api_testing_tab, values=["GET", "POST", "PUT", "DELETE"], style="TCombobox", state="readonly", justify="center")
request_type_combobox.set("GET") # Set default value
request_type_combobox.grid(row=2, column=1, padx=10, pady=10)

# Headers input (JSON format example)
ttk.Label(api_testing_tab, text="Headers (JSON format):", style="TLabel").grid(row=3, column=0, padx=10, pady=10, sticky="w")
headers_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
headers_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Authentication Token input
ttk.Label(api_testing_tab, text="Auth Token:", style="TLabel").grid(row=4, column=0, padx=10, pady=10, sticky="w")
auth_token_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
auth_token_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Request Body Entry (For POST/PUT requests)
ttk.Label(api_testing_tab, text="Request Body (JSON format):", style="TLabel").grid(row=5, column=0, padx=10, pady=10, sticky="w")
request_body_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
request_body_entry.grid(row=5, column=1, padx=10, pady=10, sticky="w")

# Response Viewer (Text area)
response_text = tk.Text(api_testing_tab, width=80, height=15, wrap="word", background="#0D0221", foreground="#EDF5FC")
response_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

# Send Request Button
ttk.Button(api_testing_tab, text="Test API", command=send_api_request, style="TButton").grid(row=7, column=0, pady=10, columnspan=3)

# Save Results Button
ttk.Button(api_testing_tab, text="Save Results", command=save_results, style="TButton").grid(row=8, column=0, pady=10, columnspan=3)

#################### 2FA Tool Tab ####################
two_factor_tab.grid_columnconfigure(0, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    two_factor_tab.grid_rowconfigure(i, weight=1)


# Input Section
frame = ttk.Frame(two_factor_tab)
frame.pack(pady=10)

time_based_var = tk.IntVar()

ttk.Label(frame, text="Provider:").grid(row=0, column=0, padx=5, pady=5)
provider_entry = ttk.Entry(frame)
provider_entry  .grid(row=0, column=1, padx=5, pady=5)

ttk.Label(frame, text="Username/Email:").grid(row=1, column=0, padx=5, pady=5)
username_entry = ttk.Entry(frame)
username_entry.grid(row=1, column=1, padx=5, pady=5)

ttk.Label(frame, text="2FA Key:").grid(row=2, column=0, padx=5, pady=5)
key_entry = ttk.Entry(frame)
key_entry.grid(row=2, column=1, padx=5, pady=5)

time_based_checkbox = ttk.Checkbutton(frame, text="Time Based", variable=time_based_var)
# Set the default value to True
time_based_var.set(True)
time_based_checkbox.grid(row=3, column=1, pady=5)

add_button = ttk.Button(frame, text="Add Account", command=add_account)
add_button.grid(row=4, column=0, columnspan=2, pady=10)

# Accounts Table
columns = ("id", "Provider", "Account", "OTP")
accounts_table = ttk.Treeview(frame, columns=columns, show="headings")
accounts_table.heading("id", text="ID")
accounts_table.heading("Provider", text="Provider")
accounts_table.heading("Account", text="Account")
accounts_table.heading("OTP", text="OTP")
accounts_table.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# make the table scrollable
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=accounts_table.yview)
scrollbar.grid(row=5, column=2, sticky="ns")
accounts_table.configure(yscrollcommand=scrollbar.set)

# combo box for accounts to choose to delete
account_combobox = ttk.Combobox(frame, values=[], state="readonly", justify="center")
account_combobox.set(1)
account_combobox.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
# Delete Button
delete_button = ttk.Button(frame, text="Delete Account", command=delete_account)
delete_button.grid(row=6, column=1, columnspan=2, pady=10)

# Start OTP Update
refresh_accounts()
update_otps()

#################### Settings Tab ####################

# Configure columns and rows for alignment
settings_tab.grid_columnconfigure(0, weight=1)
settings_tab.grid_columnconfigure(1, weight=1)
settings_tab.grid_columnconfigure(2, weight=1)
for i in range(10):  # Ensure all rows align uniformly
    settings_tab.grid_rowconfigure(i, weight=1)

# Settings Tab Title
ttk.Label(settings_tab, text="Settings", style="TLabel").grid(row=0, column=0, columnspan=3, pady=20)

# Title Label
ttk.Label(settings_tab, text="Theme Control", style="TLabel").grid(row=1, column=0, pady=20)

# List available themes in the combobox
available_themes = root.get_themes()
theme_combobox = ttk.Combobox(
    settings_tab, values=available_themes, style="TCombobox", state="readonly", justify="center"
)
theme_combobox.set(style.theme_use())  # Set the current theme as default
theme_combobox.grid(row=1, column=1, padx=10, pady=10)

# Label for font style
ttk.Label(settings_tab, text="Change Font Style", style="TLabel").grid(
    row=2, column=0, pady=20)

# List available font styles in the combobox
available_font_styles = sorted(tkFont.families())  # Get and sort available font families
font_style_combobox = ttk.Combobox(
    settings_tab, values=available_font_styles, style="TCombobox", state="readonly", justify="center"
)
font_style_combobox.set(fontStyle)  # Set the current font style as default
font_style_combobox.grid(row=2, column=1, padx=10, pady=10)

# Label for font size
ttk.Label(settings_tab, text="Change Font Size", style="TLabel").grid(
    row=3, column=0, pady=20)


# List available font sizes in the combobox
available_font_sizes = [8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
font_size_combobox = ttk.Combobox(
    settings_tab, values=available_font_sizes, style="TCombobox", state="readonly", justify="center"
)
font_size_combobox.set(fontSize)  # Set the current font size as default
font_size_combobox.grid(row=3, column=1, padx=10, pady=10)

# Button to apply font options
apply_font_size_button = ttk.Button(settings_tab, text="Apply Settings", command=update_settings, style="TButton")
apply_font_size_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

# Exit Button
ttk.Label(
    settings_tab,
    text="To close the application",
    wraplength=600,  # Adjust for better readability
    style="TLabel"
).grid(row=5, column=0, padx=10, pady=10)

exit_button = ttk.Button(settings_tab, text="Exit", command=root.destroy, style="TButton")
exit_button.grid(row=5, column=1, padx=10, pady=10)



#################### About Tab ####################

about_tab.grid_columnconfigure(0, weight=1)
about_tab.grid_columnconfigure(1, weight=1)

for i in range(4):  # Add weights for all rows
    about_tab.grid_rowconfigure(i, weight=1)


# SheeKryptor
ttk.Label(about_tab, text="SheeKryptor", style="TLabel").grid(row=0, column=0, columnspan=2, pady=20)

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
    "Version:"+version+"\n"
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

# Load settings at startup
load_settings()

root.mainloop()
