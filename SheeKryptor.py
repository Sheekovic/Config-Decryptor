import base64
import gzip
import hashlib
import json
import os
import queue
import random
import sqlite3
import string
import tarfile
import threading
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
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

# Add a Text widget for logs in the Encryptor Tab
log_output_text = None  # We'll define this later in the GUI setup

# Define output directory
encrypted_output_directory = "encrypted_files"
decrypted_output_directory = "decrypted_files"

# Global reference for GUI components
squashit_progress_bar = None
squashit_result_label = None

# Initialize ConfigParser
config = configparser.ConfigParser()
# Read settings from the INI file
config.read("settings.ini")
# Get settings with defaults if not found
# Default theme is 'equilux'
settings_theme = config.get("Settings", "theme", fallback="equilux")
# Default font style is 'OCR A Extended'
settings_font_style = config.get(
    "Settings", "font_style", fallback="OCR A Extended")
settings_font_size = config.get(
    "Settings", "font_size", fallback="16")  # Default font size is '16'

# Function to fetch title and version from the API


def fetch_title_and_version():
    try:
        # Make the GET request to fetch the data
        response = requests.get("https://sheekovic.github.io/api/api.json")
        response.raise_for_status()  # Check for request errors
        data = response.json()

        # Extract title and version
        # Fallback to default if not found
        title = data.get("title", "Default Title")
        # Fallback to default if not found
        version = data.get("version", "v1.0.0")

        return title, version
    except requests.exceptions.RequestException as e:
        messagebox.showerror(
            "API Error", f"Failed to fetch title and version: {e}")
        return "SheeKryptor", "v1.0.0"  # Fallback in case of error

# Function to generate a strong password


def generate_password(length):
    if length < 8:
        messagebox.showwarning(
            "Warning", "Password length should be at least 8 characters.")
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
        messagebox.showerror(
            "Error", "Please enter a valid number for password length.")

# Function to generate a personalized password


def generate_personalized_password():
    name = name_entry.get().strip()
    dob = dob_entry.get().strip()
    try:
        length = int(personal_password_length_entry.get())
        if length < 8:
            messagebox.showwarning(
                "Warning", "Password length should be at least 8 characters.")
            return

        if not name or not dob:
            messagebox.showwarning(
                "Warning", "Please provide both Name and Date of Birth.")
            return

        # Combine Name, Date of Birth and Password Length to create a personalized seed
        personalized_seed = name + dob + str(length)
        hashed_seed = hashlib.sha256(
            personalized_seed.encode('utf-8')).hexdigest()

        # Generate a password based on the hashed seed
        password = ''.join(random.choice(hashed_seed) for i in range(length))

        personal_password_entry.delete(0, 'end')
        personal_password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror(
            "Error", "Please enter a valid number for password length.")


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
        log("Starting encryption process...")

        # Generate a random IV for encryption
        iv = os.urandom(16)  # AES block size is 16 bytes
        log(f"Generated IV: {iv.hex()}")

        # Generate a salt for key derivation
        salt = os.urandom(16)
        log(f"Generated salt: {salt.hex()}")

        # Derive the encryption key from the password and salt
        key = derive_key(password, salt)
        log(f"Derived encryption key: {key.hex()}")

        # Read the input file data
        log(f"Opening input file: {input_file}")
        with open(input_file, 'rb') as f:
            data = f.read()
        log(f"Read {len(data)} bytes from the input file.")

        # Apply padding to make data length a multiple of the block size (16 bytes)
        # AES block size is 128 bits (16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        log(f"Padded data length: {len(padded_data)} bytes.")

        # Encrypt the file data using AES (CBC mode)
        log("Starting encryption with AES (CBC mode)...")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        log(f"Encryption completed. {
            len(encrypted_data)} bytes of encrypted data.")

        # Write the salt, IV, and encrypted data to the output file
        log(f"Saving encrypted data to output file: {output_file}")
        with open(output_file, 'wb') as f:
            f.write(salt)  # Store the salt for later key derivation
            f.write(iv)    # Store the IV
            f.write(encrypted_data)
        log(f"Output file saved successfully: {output_file}")

        messagebox.showinfo(
            "Success", f"Encryption completed. Output saved to:\n{output_file}")

    except Exception as e:
        log(f"Error occurred during encryption: {e}")
        messagebox.showerror("Error", f"Failed to encrypt file: {e}")

# Function to decrypt a file and log the actions


def decrypt_file(input_file, output_file, password):
    try:
        decryptor_log.insert("end", "Starting decryption process...\n")

        with open(input_file, 'rb') as f:
            # Read the salt, IV, and encrypted data
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()
        decryptor_log.insert("end", f"Read salt: {salt.hex()}\n")
        decryptor_log.insert("end", f"Read IV: {iv.hex()}\n")

        # Derive the decryption key from the password and salt
        key = derive_key(password, salt)
        decryptor_log.insert("end", f"Derived decryption key: {key.hex()}\n")

        # Decrypt the data using AES (CBC mode)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(
            encrypted_data) + decryptor.finalize()
        decryptor_log.insert("end", f"Decrypted data length: {
                             len(decrypted_data)} bytes.\n")

        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        decryptor_log.insert(
            "end", f"Decryption completed. Output saved to: {output_file}\n")

        messagebox.showinfo(
            "Success", f"Decryption completed. Output saved to:\n{output_file}")

    except Exception as e:
        decryptor_log.insert("end", f"Error occurred during decryption: {e}\n")
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")


# Function to browse input file
def browse_input_file_decrypt():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        decryptor_input_file_entry.delete(0, "end")  # Clear the entry
        # Insert the selected file path
        decryptor_input_file_entry.insert(0, file_path)
    else:
        messagebox.showwarning("Warning", "No file selected.")


def browse_input_file_encrypt():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        encryptor_input_file_entry.delete(0, "end")  # Clear the entry
        # Insert the selected file path
        encryptor_input_file_entry.insert(0, file_path)
    else:
        messagebox.showwarning("Warning", "No file selected.")

# Function to generate output file path with 'encrypted' or 'decrypted' appended


def get_output_file_path(input_file, is_encryption=True):
    base_name = os.path.basename(input_file)
    name, ext = os.path.splitext(base_name)

    # If it's encryption, append 'encrypted' to the filename
    if is_encryption:
        new_name = f"{name}_encrypted{ext}"
        output_directory = encrypted_output_directory
    else:
        new_name = f"{name}_decrypted{ext}"
        output_directory = decrypted_output_directory

    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    return os.path.join(output_directory, new_name)

# Function to start encryption


def start_encryption():
    input_file = encryptor_input_file_entry.get()
    password = encryptor_password_entry.get()

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    output_file = get_output_file_path(input_file, is_encryption=True)
    encrypt_file(input_file, output_file, password)

# Function to log messages to the Text widget


def log(message):
    log_output_text.insert('end', message + '\n')  # Insert the log message
    log_output_text.yview('end')  # Scroll to the end

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
        saved_font_style = config["Settings"].get(
            "font_style", "OCR A Extended")
        style.configure("TLabel", font=(saved_font_style, saved_font_size))
        style.configure("TButton", font=(saved_font_style, saved_font_size))
        style.configure("TEntry", font=(saved_font_style, saved_font_size))
        style.configure("TFrame", font=(saved_font_style, saved_font_size))
        style.configure("TCombobox", font=(saved_font_style, saved_font_size))
        style.configure("TNotebook", font=(saved_font_style, saved_font_size))
        style.configure("TCanvas", font=(saved_font_style, saved_font_size))
        style.configure("TCheckbutton", font=(
            saved_font_style, saved_font_size))
        style.configure("TScrollbar", font=(saved_font_style, saved_font_size))
        style.configure("Treeview", font=(saved_font_style, saved_font_size))
        style.configure("TRadiobutton", font=(
            saved_font_style, saved_font_size))
        style.configure("TProgressbar", font=(
            saved_font_style, saved_font_size))
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
    style.configure("TCombobox", font=(
        selected_font_style, selected_font_size))
    style.configure("TNotebook", font=(
        selected_font_style, selected_font_size))
    style.configure("TCanvas", font=(selected_font_style, selected_font_size))
    style.configure("TCheckbutton", font=(
        selected_font_style, selected_font_size))
    style.configure("TScrollbar", font=(
        selected_font_style, selected_font_size))
    style.configure("Treeview", font=(selected_font_style, selected_font_size))
    style.configure("TRadiobutton", font=(
        selected_font_style, selected_font_size))
    style.configure("TProgressbar", font=(
        selected_font_style, selected_font_size))

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
            # Parse headers as JSON if provided
            headers_dict = json.loads(headers)
    except json.JSONDecodeError:
        messagebox.showerror(
            "Error", "Invalid headers format. Please provide valid JSON.")

    # Add Authorization token to headers if provided
    if auth_token:
        headers_dict["Authorization"] = f"Bearer {auth_token}"

    try:
        # Send the API request based on the selected type
        if request_type == "GET":
            response = requests.get(api_url, headers=headers_dict)
        elif request_type == "POST":
            response = requests.post(api_url, json=json.loads(
                request_body), headers=headers_dict)
        elif request_type == "PUT":
            response = requests.put(api_url, json=json.loads(
                request_body), headers=headers_dict)
        elif request_type == "DELETE":
            response = requests.delete(api_url, headers=headers_dict)

        # Display the response in the response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Response Code: {
                             response.status_code}\n")
        response_text.insert("insert", f"Response Body:\n{response.text}")

    except requests.exceptions.RequestException as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Request failed: {e}")
    except json.JSONDecodeError as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert(
            "insert", f"Invalid request body format. Please provide valid JSON, {e}")
    except Exception as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Failed to send API request: {e}")

# Optional: Save Results Button (save to a text file)


def save_results():
    try:
        response_data = response_text.get(1.0, "end")
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
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
    cursor.execute(
        "SELECT MAX(SUBSTR(id, 5, LENGTH(id))) FROM accounts WHERE id LIKE ?", (custom_id + '%',))
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
    cursor.execute(
        "SELECT id, provider, username, key, time_based FROM accounts")
    accounts = cursor.fetchall()  # Store the accounts to use later

    # Insert rows into the table
    for account in accounts:
        otp = pyotp.TOTP(account[3])
        current_otp = otp.now()
        accounts_table.insert("", "end", values=(
            account[0], account[1], account[2], current_otp))

    # Update the combobox values with account ids
    account_combobox['values'] = [account[0] for account in accounts]


def update_otps():
    for child in accounts_table.get_children():
        item = accounts_table.item(child)
        username = item['values'][0]

        cursor.execute(
            "SELECT key FROM accounts WHERE username = ?", (username,))
        account = cursor.fetchone()
        if account:
            otp = pyotp.TOTP(account[0])
            current_otp = otp.now()
            accounts_table.item(child, values=(username, current_otp))

    root.after(1000, update_otps)  # Refresh OTPs every second


def unsquashit(input_file, output_dir):
    """Decompress the Squashed file into the same directory as the input file."""
    try:
        # Ensure input_file is a string, not a list
        if isinstance(input_file, list):
            input_file = input_file[0]  # Process the first file if it's a list

        # Define the output file path to be in the same directory as input file
        output_file_path = os.path.join(
            output_dir, os.path.basename(input_file).replace(".zlib", ""))

        # Read the input file
        with open(input_file, "rb") as f_in:
            data = f_in.read()

        # Attempt decompression
        try:
            decompressed_data = zlib.decompress(data)
        except zlib.error as e:
            return f"Decompression failed: {e}"

        # Save the decompressed data to the output directory (same as input file)
        with open(output_file_path, "wb") as f_out:
            f_out.write(decompressed_data)

        return f"Unsquash completed successfully! Saved to {output_file_path}"

    except Exception as e:
        return f"Unsquash failed: {str(e)}"


def squashit(input_files, output_file, compression_level=9, compression_format='zlib'):
    """Compress the selected files into a squash file with the given compression format."""
    try:
        total_size = sum(os.path.getsize(f)
                         for f in input_files)  # Total size of all files
        compressed_data = bytearray()
        compressed_data_size = 0

        # Create a queue for progress updates
        progress_queue = queue.Queue()

        # Define a function to compress each file
        def compress_file(file_path):
            nonlocal compressed_data, compressed_data_size
            with open(file_path, "rb") as f:
                data = f.read()

            # Compress data in chunks and update progress via the queue
            for i in range(0, len(data), 1024 * 1024):  # 1MB chunk size
                chunk = data[i:i + 1024 * 1024]
                if compression_format == 'gz':
                    compressed_chunk = gzip.compress(
                        chunk, compresslevel=compression_level)
                elif compression_format == 'tar.zlib':
                    compressed_chunk = zlib.compress(
                        chunk, level=compression_level)
                else:  # Default zlib compression
                    compressed_chunk = zlib.compress(
                        chunk, level=compression_level)

                compressed_data.extend(compressed_chunk)
                compressed_data_size += len(compressed_chunk)

                # Put progress data in the queue
                progress = (compressed_data_size / total_size) * 100
                progress_queue.put(progress)

        # Start threads for each file
        threads = []
        for file in input_files:
            thread = threading.Thread(target=compress_file, args=(file,))
            thread.start()
            threads.append(thread)

        # Update progress bar from the main thread
        def update_progress():
            if not progress_queue.empty():
                progress = progress_queue.get()
                squashit_progress_bar["value"] = progress
                squashit_progress_bar.update()
                # Schedule next update
                squashit_tab.after(100, update_progress)

        update_progress()  # Start updating progress

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Save the compressed data to the output file
        with open(output_file, "wb") as f_out:
            f_out.write(compressed_data)

        # Generate checksum
        file_hash = hashlib.sha256(compressed_data).hexdigest()
        squashit_result_label.config(text=f"Compression completed! Checksum: {
                                     file_hash}", foreground="green")
        return f"Compression completed successfully! Saved to {output_file} with checksum: {file_hash}"

    except Exception as e:
        squashit_result_label.config(text=f"Compression failed: {
                                     str(e)}", foreground="red")
        return f"Compression failed: {e}"


def browse_file(entry):
    """Browse and select files."""
    file_paths = filedialog.askopenfilenames()
    if file_paths:
        entry.delete(0, tk.END)
        entry.insert(0, ', '.join(file_paths))


def browse_folder(entry):
    """Browse and select a folder."""
    folder_path = filedialog.askdirectory()
    if folder_path:
        entry.delete(0, tk.END)
        entry.insert(0, folder_path)


def browse_output(entry, operation_type):
    """Browse and select the output file or directory based on the operation."""
    if operation_type == 'SquashIt':
        # For SquashIt, allow the user to select a compressed file to save
        output_path = filedialog.asksaveasfilename(defaultextension=".zlib", filetypes=[
            ("Zlib Files", "*.zlib"), ("All Files", "*.*")])
    elif operation_type == 'UnSquashIt':
        # For UnSquashIt, allow the user to select a folder for decompressed files
        output_path = filedialog.askdirectory()  # Asking for a directory path

    if output_path:
        entry.delete(0, tk.END)
        entry.insert(0, output_path)

# Function to handle setting the selected compression format


def set_compression_format(event=None):
    """Set the selected compression format."""
    global selected_format
    selected_format = format_combobox.get()

# Function to handle conversion ConvertX


def convertx(input_files, conversion_type):
    # Clear the result text box before starting a new conversion
    convertx_result_text.delete(1.0, tk.END)

    # Process each input file
    for input_file in input_files:
        # Get the folder of the input file
        folder_path = os.path.dirname(input_file)
        # Get the filename without path
        base_name = os.path.basename(input_file)

        # Add _{conversion_type} to the output filename
        if conversion_type == "Image to Base64":
            output_file = os.path.join(
                folder_path, f"{os.path.splitext(base_name)[0]}_base64.txt")
        elif conversion_type == "Base64 to Image":
            output_file = os.path.join(
                folder_path, f"{os.path.splitext(base_name)[0]}_image.png")
        elif conversion_type == "Text Encoding":
            output_file = os.path.join(folder_path, f"{os.path.splitext(
                base_name)[0]}_encoded{os.path.splitext(base_name)[1]}")
        elif conversion_type == "Base64 to Text":
            output_file = os.path.join(folder_path, f"{os.path.splitext(
                base_name)[0]}_decoded{os.path.splitext(base_name)[1]}")

        if conversion_type == "Image to Base64":
            convert_image_to_base64(input_file, output_file)
        elif conversion_type == "Base64 to Image":
            convert_base64_to_image(input_file, output_file)
        elif conversion_type == "Text Encoding":
            convert_text_encoding(input_file, output_file)
        elif conversion_type == "Base64 to Text":
            convert_base64_to_text(input_file, output_file)

        # Display output file location in result label
        convertx_result_label.config(text=f"Output saved to: {output_file}")

# Conversion Function: Image to Base64


def convert_image_to_base64(input_file, output_file):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
            base64_data = base64.b64encode(data).decode("utf-8")
            with open(output_file, "w") as f_out:
                f_out.write(base64_data)

        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Image {
                                    input_file} converted to Base64 successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Base64 to Image


def convert_base64_to_image(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            base64_data = f.read()
            decoded_data = base64.b64decode(base64_data)
            with open(output_file, "wb") as f_out:
                f_out.write(decoded_data)
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Base64 file {
                                    input_file} converted to image successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Text Encoding


def convert_text_encoding(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            text_data = f.read()
            encoded_data = text_data.encode("utf-8")
            with open(output_file, "wb") as f_out:
                f_out.write(encoded_data)
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Text from {
                                    input_file} encoded to UTF-8 successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Base64 to Text


def convert_base64_to_text(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            base64_data = f.read()
            decoded_data = base64.b64decode(base64_data)
            with open(output_file, "w") as f_out:
                f_out.write(decoded_data.decode("utf-8"))
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Base64 file {
                                    input_file} decoded to text successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Function to generate temporary mail


def generate_temp_mail():
    # Declare globals for use in `refresh_messages`
    global headers, messages_url, messages_result_text
    # Get Available Domains
    domain_response = requests.get("https://api.mail.tm/domains")
    domain_response.raise_for_status()  # Check for request errors
    domain_data = domain_response.json()

    # Get the first domain string
    domain = domain_data['hydra:member'][0]['domain']

    # Get Name and Password from Entry Fields
    name = name_entry.get().strip()
    password = password_entry.get().strip()


    # Create an account
    account_url = "https://api.mail.tm/accounts"
    account_data = {
        "address": name + "@" + domain,
        "password": password
    }
    account_response = requests.post(account_url, json=account_data)
    account_response.raise_for_status()
    account_details = account_response.json()

    # print account_details in account_id_label
    account_id_label.config(text="Account ID: " + account_details['id'])
    account_address_label.config(text="Address: " + account_details['address'])
    account_quota_label.config(text="Quota: " + str(account_details['quota']))
    account_created_at_label.config(text="Created At: " + account_details['createdAt'])

    # Log in to get the JWT token
    token_url = "https://api.mail.tm/token"
    login_data = {
        "address": account_details['address'],
        "password": password
    }
    token_response = requests.post(token_url, json=login_data)
    token_response.raise_for_status()
    token_details = token_response.json()

    jwt_token = token_details['token']

    # Use the JWT token to fetch messages
    messages_url = "https://api.mail.tm/messages"
    headers = {
        "Authorization": f"Bearer {jwt_token}"
    }
    messages_response = requests.get(messages_url, headers=headers)
    messages_response.raise_for_status()
    messages_data = messages_response.json()

    # print messages_data in messages_result_text
    messages_result_text.delete("1.0", tk.END)
    messages_result_text.insert(tk.END, str(messages_data))

# Refresh Messages Function
def refresh_messages():
    global headers, messages_url, messages_result_text  # Use global variables defined in `generate_temp_mail`
    messages_response = requests.get(messages_url, headers=headers)
    messages_response.raise_for_status()
    messages_data = messages_response.json()

    # Clear existing text in the result box
    messages_result_text.delete("1.0", tk.END)

    # Loop through each message and format its relevant data
    for message in messages_data['hydra:member']:
        message_info = (
            f"id: {message['id']}\n"
            f"from: {message['from']['address']}\n"
            f"subject: {message['subject']}\n"
            f"intro: {message['intro']}\n"
            f"seen: {message['seen']}\n"
            f"createdAt: {message['createdAt']}\n"
            "------------------------\n"
        )
        messages_result_text.insert(tk.END, message_info)


# Function to handle about SheeKryptor
def about_sheekryptor():
    messagebox.showinfo(
        "About SheeKryptor", "SheeKryptor is a secure encryption and decryption tool.\n\nVersion: v1.0.0\n\nAuthor: Ahmeed Sheeko\n\nContact: sheekovic@gmail.com")


"""
################## Main GUI ##################
this is the main GUI
you can add widgets here
"""
root = ThemedTk(theme='equilux')

# Fetch title and version from the API
title, version = fetch_title_and_version()

root.title(f"{title} {version}")

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
gray = "#433e3f"

# Create the style object before creating tabs
style = ttk.Style()

# Defult Style Configuration
style.configure("TNotebook", background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TEntry', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TCombobox', font=(fontStyle, fontSize))
style.map('TCombobox', fieldbackground=[
          ('readonly', black)], foreground=[('readonly', green)])
# Configure the default button style
style.configure('TButton', background="black",
                foreground="green", font=(fontStyle, fontSize))
# Map the button style for different states (active, pressed, and hover)
style.map('TButton',
          foreground=[('pressed', 'white'),  # Green text when pressed
                      ('active', green)])
style.configure('TLabel', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TFrame', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TCheckbutton', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TCanvas', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TFrame', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TScrollbar', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('Treeview', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TRadiobutton', background=black,
                foreground=green, font=(fontStyle, fontSize))
style.configure('TProgressbar', background=black,
                foreground=green, font=(fontStyle, fontSize))

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

# SquashIt tab
squashit_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(squashit_tab, text="SquashIt", padding=10)

# ConvertX tab
convertx_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(convertx_tab, text="ConvertX", padding=10)

# Temp Mail tab
temp_mail_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(temp_mail_tab, text="Temp Mail", padding=10)

# Settings tab
settings_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(settings_tab, text="Settings", padding=10)

# About tab
about_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(about_tab, text="About", padding=10)

# Center the tabs in the window
tab_control.grid(row=0, column=0, sticky="nsew")

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

ttk.Label(decryptor_tab, text="Input File:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")

ttk.Button(decryptor_tab, text="Browse", command=browse_input_file_decrypt,
           style="TButton").grid(row=2, column=2, padx=10, pady=10)

# Ensure we are not using a custom style for the input field and check behavior without it
decryptor_input_file_entry = ttk.Entry(decryptor_tab, width=70, style="TEntry")
decryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

ttk.Label(decryptor_tab, text="Password:", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="e")
decryptor_password_entry = ttk.Entry(decryptor_tab, width=70, style="TEntry")
decryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(decryptor_tab, text="Decrypt", command=start_decryption,
           style="TButton").grid(row=4, column=0, columnspan=3, pady=20)

# Log Text Area
decryptor_log = tk.Text(decryptor_tab, width=80, height=10, wrap="word",
                        state="normal", background=gray, foreground=green)
decryptor_log.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

"""
#################### Encryptor Tab ####################
This tab provides the interface for encrypting files.
Users can input the file to encrypt, provide the password, and initiate the encryption process.
The layout ensures all widgets are centered and evenly spaced.
"""
# Configure columns and rows for alignment
encryptor_tab.grid_columnconfigure(0, weight=1)
encryptor_tab.grid_columnconfigure(1, weight=1)
encryptor_tab.grid_columnconfigure(2, weight=1)
for i in range(6):  # Ensure all rows align uniformly
    encryptor_tab.grid_rowconfigure(i, weight=1)

# Encryptor Tab Title
ttk.Label(encryptor_tab, text="Encryptor", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

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
ttk.Label(encryptor_tab, text="Input File:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")
encryptor_input_file_entry = ttk.Entry(encryptor_tab, width=70, style="TEntry")
encryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
ttk.Button(encryptor_tab, text="Browse", command=browse_input_file_encrypt,
           style="TButton").grid(row=2, column=2, padx=10, pady=10)

ttk.Label(encryptor_tab, text="Password:", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="e")
encryptor_password_entry = ttk.Entry(encryptor_tab, width=70, style="TEntry")
encryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(encryptor_tab, text="Encrypt", command=start_encryption,
           style="TButton").grid(row=4, column=0, columnspan=3, pady=20)

# log output text widget to display logs
log_output_text = tk.Text(encryptor_tab, width=80, height=10,
                          wrap="word", background=gray, foreground=green)
log_output_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10)
log_output_text.config(state='normal')
log_output_text.insert('end', 'Encryption Log:\n')

"""
#################### PWD Generator Tab ####################
This tab provides the interface for generating strong passwords.
Users can input the desired password length and click the "Generate Password" button.
The layout ensures all widgets are centered and evenly spaced.
"""
# Configure columns and rows for alignment
pwd_generator_tab.grid_columnconfigure(0, weight=1)
pwd_generator_tab.grid_columnconfigure(1, weight=1)

for i in range(10):  # Add weights for all rows
    pwd_generator_tab.grid_rowconfigure(i, weight=1)

# Strong Password Generator Section
ttk.Label(pwd_generator_tab, text="Strong Password Generator",
          style="TLabel").grid(row=0, column=0, columnspan=2, pady=20)

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
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")
password_length_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
password_length_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Button to generate password
ttk.Button(pwd_generator_tab, text="Generate Password", command=create_password,
           style="TButton").grid(row=3, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(
    row=4, column=0, padx=10, pady=10, sticky="e")
password_entry = ttk.Entry(pwd_generator_tab, width=40, style="TEntry")
password_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Personalized Password Generator Section
ttk.Label(pwd_generator_tab, text="Personalized Password Generator",
          style="TLabel").grid(row=5, column=0, columnspan=2, pady=20)

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
ttk.Label(pwd_generator_tab, text="Name:", style="TLabel").grid(
    row=7, column=0, padx=10, pady=10, sticky="e")
name_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
name_entry.grid(row=7, column=1, padx=10, pady=10, sticky="w")

# Date of Birth input field
ttk.Label(pwd_generator_tab, text="Date of Birth:", style="TLabel").grid(
    row=8, column=0, padx=10, pady=10, sticky="e")
dob_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
dob_entry.grid(row=8, column=1, padx=10, pady=10, sticky="w")

# Password Length input field
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(
    row=9, column=0, padx=10, pady=10, sticky="e")
personal_password_length_entry = ttk.Entry(
    pwd_generator_tab, width=20, style="TEntry")
personal_password_length_entry.grid(
    row=9, column=1, padx=10, pady=10, sticky="w")

# Button to generate personalized password
ttk.Button(pwd_generator_tab, text="Generate Password", command=generate_personalized_password,
           style="TButton").grid(row=10, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(
    row=11, column=0, padx=10, pady=10, sticky="e")
personal_password_entry = ttk.Entry(
    pwd_generator_tab, width=40, style="TEntry")
personal_password_entry.grid(row=11, column=1, padx=10, pady=10, sticky="w")

"""
#################### API Test Tab ####################
this tab is for api testing
"""
# Configure columns and rows for centering
api_testing_tab.grid_columnconfigure(0, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    api_testing_tab.grid_rowconfigure(i, weight=1)

# API Testing Tab Title
ttk.Label(api_testing_tab, text="API Testing", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# API URL Entry
ttk.Label(api_testing_tab, text="API URL:", style="TLabel").grid(
    row=1, column=0, padx=10, pady=10, sticky="w")  # Align label to the right
api_url_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
api_url_entry.grid(row=1, column=1, padx=10, pady=10, sticky="e")

# API Request Type (GET, POST, PUT, DELETE)
ttk.Label(api_testing_tab, text="Request Type:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="w")
request_type_combobox = ttk.Combobox(api_testing_tab, values=[
                                     "GET", "POST", "PUT", "DELETE"], style="TCombobox", state="readonly", justify="center")
request_type_combobox.set("GET")  # Set default value
request_type_combobox.grid(row=2, column=1, padx=10, pady=10)

# Headers input (JSON format example)
ttk.Label(api_testing_tab, text="Headers (JSON format):", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="w")
headers_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
headers_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Authentication Token input
ttk.Label(api_testing_tab, text="Auth Token:", style="TLabel").grid(
    row=4, column=0, padx=10, pady=10, sticky="w")
auth_token_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
auth_token_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Request Body Entry (For POST/PUT requests)
ttk.Label(api_testing_tab, text="Request Body (JSON format):",
          style="TLabel").grid(row=5, column=0, padx=10, pady=10, sticky="w")
request_body_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
request_body_entry.grid(row=5, column=1, padx=10, pady=10, sticky="w")

# Response Viewer (Text area)
response_text = tk.Text(api_testing_tab, width=80, height=15,
                        wrap="word", background=gray, foreground=green)
response_text.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

# Send Request Button
ttk.Button(api_testing_tab, text="Test API", command=send_api_request,
           style="TButton").grid(row=6, column=0, pady=10, columnspan=3)

# Save Results Button
ttk.Button(api_testing_tab, text="Save Results", command=save_results,
           style="TButton").grid(row=8, column=0, pady=10, columnspan=3)

"""
#################### 2FA Tool Tab ####################
this tab is for 2FA tool functionality
"""
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

time_based_checkbox = ttk.Checkbutton(
    frame, text="Time Based", variable=time_based_var)
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
scrollbar = ttk.Scrollbar(frame, orient="vertical",
                          command=accounts_table.yview)
scrollbar.grid(row=5, column=2, sticky="ns")
accounts_table.configure(yscrollcommand=scrollbar.set)

# combo box for accounts to choose to delete
account_combobox = ttk.Combobox(
    frame, values=[], state="readonly", justify="center")
account_combobox.set(1)
account_combobox.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
# Delete Button
delete_button = ttk.Button(
    frame, text="Delete Account", command=delete_account)
delete_button.grid(row=6, column=1, columnspan=2, pady=10)

# Start OTP Update
refresh_accounts()
update_otps()


"""
#################### SquashIt Tab ####################
SquashIt is a tool that compresses files to the extreme using advanced algorithms (ZPAQ or PAQ8).
"""
squashit_tab.grid_columnconfigure(0, weight=1)
squashit_tab.grid_columnconfigure(1, weight=1)
squashit_tab.grid_columnconfigure(2, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    squashit_tab.grid_rowconfigure(i, weight=1)

# SquashIt Tab Title
ttk.Label(squashit_tab, text="SquashIt", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Description for the SquashIt tool
ttk.Label(
    squashit_tab,
    text=(
        "The SquashIt tool allows you to compress files to the extreme using advanced algorithms. "
        "Select the file you wish to compress, choose the compression level, and click 'Compress' "
        "to generate a compressed file."
    ),
    wraplength=600,  # Adjust width for better readability
    style="TLabel"
).grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Compression Level ComboBox
ttk.Label(squashit_tab, text="Compression Level (0 to 9)").grid(
    row=2, column=0, padx=10, pady=10)
compression_level_combobox = ttk.Combobox(
    squashit_tab, values=[str(i) for i in range(10)], state="readonly", width=5
)
compression_level_combobox.set(9)  # Default value
compression_level_combobox.grid(row=2, column=1, padx=10, pady=10)

# Input Files Selection
ttk.Label(squashit_tab, text="Select Files:").grid(
    row=3, column=0, padx=10, pady=10)
input_files_entry = ttk.Entry(squashit_tab, width=40)
input_files_entry.grid(row=3, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_file(
    input_files_entry)).grid(row=3, column=2, padx=10, pady=10)

# Output File Selection
ttk.Label(squashit_tab, text="Output File:").grid(
    row=4, column=0, padx=10, pady=10)
output_file_entry = ttk.Entry(squashit_tab, width=40)
output_file_entry.grid(row=4, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_output(
    output_file_entry, 'SquashIt')).grid(row=4, column=2, padx=10, pady=10)

# Compression Format Selection (Updated to Combobox)
ttk.Label(squashit_tab, text="Compression Format:").grid(
    row=5, column=0, padx=10, pady=10)

format_combobox = ttk.Combobox(
    squashit_tab, values=["zlib", "gz", "tar.zlib"], state="readonly", width=15
)
format_combobox.set('zlib')  # Default value
format_combobox.grid(row=5, column=1, padx=10, pady=10)

# Compression Button
ttk.Button(squashit_tab, text="SquashIT", command=lambda: squashit(input_files_entry.get().split(', '), output_file_entry.get(), int(compression_level_combobox.get()), format_combobox.get())).grid(row=6, column=0, columnspan=3, pady=20)

# Result Label
squashit_result_label = ttk.Label(squashit_tab, text="", foreground="green", font=(fontStyle, 8))
squashit_result_label.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

# input Label for the decompression tool
ttk.Label(squashit_tab, text="Input Files:").grid(
    row=9, column=0, padx=10, pady=10)
unsquashit_input_files_entry = ttk.Entry(squashit_tab, width=40)
unsquashit_input_files_entry.grid(row=9, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_file(
    unsquashit_input_files_entry)).grid(row=9, column=2, padx=10, pady=10)

# Decompression Button (updated to pass the correct arguments)
ttk.Button(squashit_tab, text="UnSquashIT", command=lambda: unsquashit(unsquashit_input_files_entry.get().split(', '), '')).grid(row=10, column=0, columnspan=3, pady=20)

# result Label
unsquashit_result_label = ttk.Label(squashit_tab, text="", foreground="green", font=(fontStyle, 8))
unsquashit_result_label.grid(row=11, column=0, columnspan=3, padx=10, pady=10)



"""
#################### ConvertX Tab ####################
"""
# Conversion tab layout
convertx_tab.grid_columnconfigure(0, weight=1)
convertx_tab.grid_columnconfigure(1, weight=1)
convertx_tab.grid_columnconfigure(2, weight=1)

for i in range(10):  # Ensure all rows align uniformly
    convertx_tab.grid_rowconfigure(i, weight=1)

# ConvertX Tab Title
ttk.Label(convertx_tab, text="ConvertX", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Description for the ConvertX tool
ttk.Label(convertx_tab, text="ConvertX is a powerful tool for converting between various formats "
                             "including image to base64, base64 to image, text encoding conversions, "
                             "and much more. Choose your conversion type and proceed with ease.",
          wraplength=600,  # Adjust width for better readability
          style="TLabel").grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Conversion Type ComboBox
ttk.Label(convertx_tab, text="Conversion Type").grid(
    row=2, column=0, padx=10, pady=10)
conversion_type_combobox = ttk.Combobox(
    convertx_tab, values=["Image to Base64", "Base64 to Image", "Text Encoding", "Base64 to Text"], state="readonly", width=15
)
conversion_type_combobox.set("Image to Base64")  # Default value
conversion_type_combobox.grid(row=2, column=1, padx=10, pady=10)

# Input Files Selection
ttk.Label(convertx_tab, text="Select Files:").grid(
    row=3, column=0, padx=10, pady=10)
input_files_entry = ttk.Entry(convertx_tab, width=40)
input_files_entry.grid(row=3, column=1, padx=10, pady=10)

ttk.Button(convertx_tab, text="Browse", command=lambda: browse_file(input_files_entry)).grid(row=3, column=2, padx=10, pady=10)

# Conversion Button
ttk.Button(convertx_tab, text="Convert", command=lambda: convertx(
    input_files_entry.get().split(', '), conversion_type_combobox.get())).grid(row=5, column=0, columnspan=3, pady=20)

# Result Label
convertx_result_label = ttk.Label(convertx_tab, text="", foreground="green", font=("Arial", 8))
convertx_result_label.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

# Result text box area for ConvertX
convertx_result_text = tk.Text(convertx_tab, height=15, width=80, wrap="word", background=gray, foreground=green)
convertx_result_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)


"""
#################### Temp Mail Tab ####################
Temp Mail to Generate a Temporary Email Address
"""

# configure columns and rows for alignment
temp_mail_tab.grid_columnconfigure(0, weight=1)
temp_mail_tab.grid_columnconfigure(1, weight=1)
temp_mail_tab.grid_columnconfigure(2, weight=1)
for i in range(10):  # Ensure all rows align uniformly
    temp_mail_tab.grid_rowconfigure(i, weight=1)

# Temp Mail Tab Title
ttk.Label(temp_mail_tab, text="Temp Mail", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Name Label
ttk.Label(temp_mail_tab, text="Name:", style="TLabel").grid(
    row=1, column=0, padx=10, pady=10)

# Name Entry
name_entry = ttk.Entry(temp_mail_tab, width=40)
name_entry.grid(row=1, column=1, padx=10, pady=10)

# Password Label
ttk.Label(temp_mail_tab, text="Password:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10)

# Password Entry
password_entry = ttk.Entry(temp_mail_tab, show="*", width=40)
password_entry.grid(row=2, column=1, padx=10, pady=10)

# Generate Temp Mail Button
ttk.Button(temp_mail_tab, text="Generate Temp Mail", command=generate_temp_mail).grid(
    row=3, column=0, columnspan=3, pady=20)

# Account ID Label
account_id_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_id_label.grid(row=4, column=0, padx=10, pady=10, columnspan=3)

# Account Address Label
account_address_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_address_label.grid(row=5, column=0, padx=10, pady=10, columnspan=3)

# Account Quota Label
account_quota_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_quota_label.grid(row=6, column=0, padx=10, pady=10, columnspan=3)

# Account Created At Label
account_created_at_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_created_at_label.grid(row=7, column=0, padx=10, pady=10, columnspan=3)

# Result text box area for Messages
messages_result_text = tk.Text(temp_mail_tab, height=15, width=80, wrap="word", background=gray, foreground=green)
messages_result_text.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

# Refresh Button
ttk.Button(temp_mail_tab, text="Refresh", command=refresh_messages).grid(
    row=9, column=0, columnspan=3, pady=20)



"""
#################### Settings Tab ####################
settings_tab is a tab that allows users to configure various settings, such as theme, font style, and font size.
"""

# Configure columns and rows for alignment
settings_tab.grid_columnconfigure(0, weight=1)
settings_tab.grid_columnconfigure(1, weight=1)
settings_tab.grid_columnconfigure(2, weight=1)
for i in range(10):  # Ensure all rows align uniformly
    settings_tab.grid_rowconfigure(i, weight=1)

# Settings Tab Title
ttk.Label(settings_tab, text="Settings", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Title Label
ttk.Label(settings_tab, text="Theme Control",
          style="TLabel").grid(row=1, column=0, pady=20)

# List available themes in the combobox
available_themes = root.get_themes()
theme_combobox = ttk.Combobox(
    settings_tab, values=available_themes, style="TCombobox", state="readonly", justify="center"
)
theme_combobox.set(settings_theme)  # Set the current theme as default
theme_combobox.grid(row=1, column=1, padx=10, pady=10)

# Label for font style
ttk.Label(settings_tab, text="Change Font Style", style="TLabel").grid(
    row=2, column=0, pady=20)

# List available font styles in the combobox
# Get and sort available font families
available_font_styles = sorted(tkFont.families())
font_style_combobox = ttk.Combobox(
    settings_tab, values=available_font_styles, style="TCombobox", state="readonly", justify="center"
)
font_style_combobox.set(settings_font_style)  # Set the current font style as default
font_style_combobox.grid(row=2, column=1, padx=10, pady=10)

# Label for font size
ttk.Label(settings_tab, text="Change Font Size", style="TLabel").grid(
    row=3, column=0, pady=20)


# List available font sizes in the combobox
available_font_sizes = [8, 10, 12, 14, 16, 18,
                        20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
font_size_combobox = ttk.Combobox(
    settings_tab, values=available_font_sizes, style="TCombobox", state="readonly", justify="center"
)
font_size_combobox.set(settings_font_size)  # Set the current font size as default
font_size_combobox.grid(row=3, column=1, padx=10, pady=10)

# Button to apply font options
apply_font_size_button = ttk.Button(
    settings_tab, text="Apply Settings", command=update_settings, style="TButton")
apply_font_size_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

# Exit Button
ttk.Label(
    settings_tab,
    text="To close the application",
    wraplength=600,  # Adjust for better readability
    style="TLabel"
).grid(row=5, column=0, padx=10, pady=10)

exit_button = ttk.Button(settings_tab, text="Exit",
                         command=root.destroy, style="TButton")
exit_button.grid(row=5, column=1, padx=10, pady=10)

"""
#################### About Tab ####################
About Tab is a tab that provides information about the application and its features.
"""

about_tab.grid_columnconfigure(0, weight=1)
about_tab.grid_columnconfigure(1, weight=1)

for i in range(4):  # Add weights for all rows
    about_tab.grid_rowconfigure(i, weight=1)


# SheeKryptor
ttk.Label(about_tab, text="SheeKryptor", style="TLabel").grid(
    row=0, column=0, columnspan=2, pady=20)

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
    "- API Testing & Development\n"
    "- 2FA Tool - Two Factor Authentication\n"
    "- SquashIt - File Compression\n"
    "- Support for Multiple Themes\n"
    "- Intuitive User Interface\n"
    "- More Coming Soon..."
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
