from tkinter import Tk, Canvas, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Function to decrypt the file
def decrypt_file(input_file, output_file, key, iv):
    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"Decryption completed. Output saved to:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")

# Function to browse input file
def browse_input_file():
    file_path = filedialog.askopenfilename(title="Select Encrypted File")
    if file_path:
        input_file_entry.delete(0, "end")
        input_file_entry.insert(0, file_path)

# Function to browse output file
def browse_output_file():
    file_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
    if file_path:
        output_file_entry.delete(0, "end")
        output_file_entry.insert(0, file_path)

# Function to start decryption
def start_decryption():
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    key = key_entry.get().encode('utf-8')
    iv = iv_entry.get().encode('utf-8')

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not output_file:
        messagebox.showerror("Error", "Please specify an output file.")
        return
    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 bytes long.")
        return
    if len(iv) != 16:
        messagebox.showerror("Error", "IV must be 16 bytes long.")
        return

    decrypt_file(input_file, output_file, key, iv)

# Main GUI
root = Tk()
root.title("Config Decryptor by SHEEKOVIC")
root.geometry("720x600")
root.resizable(True, True)  # Enable resizing
root.configure(bg="black")
root.iconbitmap("assets/decryptor.ico")
fontStyle = "OCR A Extended"

# Create Canvas for Glowing Text Effects
canvas = Canvas(root, bg="black", highlightthickness=0)
canvas.grid(row=1, column=0, sticky="nsew")

# Add Glowing Green Title
shadow_offset = 2
def create_glowing_text(canvas, text, x, y, font, glow_color, text_color):
    for offset in range(1, 6):  # Glow layers
        canvas.create_text(
            x + offset, y + offset, text=text, fill=glow_color, font=font, anchor="center"
        )
    canvas.create_text(x, y, text=text, fill=text_color, font=font, anchor="center")

# Title label (this is now outside the canvas and placed at the top)
title_label = Label(root, text="Config Decryptor by SHEEKOVIC", font=(fontStyle, 24, "bold"), fg="#00cc00", bg="black")
title_label.grid(row=0, column=0, pady=20)
root.grid_rowconfigure(0, weight=1)

# Configure grid weights to allow resizing
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

# Input Fields and Buttons
Label(canvas, text="Input File:", font=(fontStyle, 12), bg="black", fg="green").grid(row=1, column=0, padx=10, pady=5, sticky="e")
input_file_entry = Entry(canvas, width=40, bg="black", fg="green", insertbackground="green", font=(fontStyle, 12))
input_file_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")
Button(canvas, text="Browse", command=browse_input_file, bg="black", fg="green", font=(fontStyle, 10)).grid(row=1, column=2, padx=10, pady=5)

Label(canvas, text="Output File:", font=(fontStyle, 12), bg="black", fg="green").grid(row=2, column=0, padx=10, pady=5, sticky="e")
output_file_entry = Entry(canvas, width=40, bg="black", fg="green", insertbackground="green", font=(fontStyle, 12))
output_file_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
Button(canvas, text="Browse", command=browse_output_file, bg="black", fg="green", font=(fontStyle, 10)).grid(row=2, column=2, padx=10, pady=5)

Label(canvas, text="Key (16 bytes):", font=(fontStyle, 12), bg="black", fg="green").grid(row=3, column=0, padx=10, pady=5, sticky="e")
key_entry = Entry(canvas, width=40, bg="black", fg="green", insertbackground="green", font=(fontStyle, 12))
key_entry.grid(row=3, column=1, padx=10, pady=5, sticky="w")

Label(canvas, text="IV (16 bytes):", font=(fontStyle, 12), bg="black", fg="green").grid(row=4, column=0, padx=10, pady=5, sticky="e")
iv_entry = Entry(canvas, width=40, bg="black", fg="green", insertbackground="green", font=(fontStyle, 12))
iv_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

Button(canvas, text="Decrypt", command=start_decryption, bg="black", fg="green", font=(fontStyle, 12, "bold")).grid(row=5, column=0, columnspan=3, pady=20)

root.mainloop()
