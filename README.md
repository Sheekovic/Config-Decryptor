# SheeKryptor!!

SheeKryptor is a secure file encryption and decryption tool designed for ease of use. It allows users to encrypt and decrypt files with strong AES encryption. The tool also includes password generation and personalization features for enhanced security.

## Features

- **File Encryption**: Encrypt files securely with AES (CBC mode) using a user-defined password.
- **File Decryption**: Decrypt encrypted files by providing the correct password.
- **Password Generator**: Generate strong passwords with the option to create personalized passwords based on your name and date of birth.
- **API Testing**: Test any API endpoints with the SheeKryptor API , which supports GET, POST, PUT, and DELETE requests.
- **User-Friendly GUI**: Simple and intuitive graphical interface built using Tkinter.
- **Customizable Settings**: Change the theme and font style/size for a personalized experience.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/sheekovic/SheeKryptor.git
   cd SheeKryptor
   ```
   or from GitHub CLI
   ```bash
   gh repo clone Sheekovic/SheeKryptor
   cd SheeKryptor
   ```

2. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the program**:
   ```bash
   python sheekryptor.py
   ```

## Requirements

- Python 3.x
- `cryptography` package
- `tkinter` (for GUI)
- `ttkthemes` (for theme styling)

## Usage

### Encrypt a File
1. Go to the "Encryptor" tab.
2. Select the file you wish to encrypt by clicking "Browse".
3. Enter a strong password.
4. Click the "Encrypt" button to generate the encrypted file.
5. The encrypted file will be saved in the `encrypted_files` folder with `_encrypted` appended to the filename.

### Decrypt a File
1. Go to the "Decryptor" tab.
2. Select the encrypted file by clicking "Browse".
3. Enter the password used for encryption.
4. Click the "Decrypt" button to retrieve the original file.
5. The decrypted file will be saved in the `decrypted_files` folder with `_decrypted` appended to the filename.

### Password Generator
1. Go to the "PWD Generator" tab.
2. Choose the length for the password you want to generate.
3. Click "Generate" to create a random strong password.

### Personalized Password
1. Go to the "PWD Generator" tab.
2. Enter your name and date of birth.
3. Choose the password length.
4. Click "Generate" to create a personalized password based on your details.

### API Testing
1. Go to the "API Testing" tab.
2. Enter the API endpoint URL.
3. Select the HTTP method (GET, POST, PUT, DELETE).
4. Enter any required parameters.
5. click "Test API" to send the request and view the response.
6. Save Results to a text file by clicking "Save Results".

## Themes and Font Customization
1. Go to the "Settings" tab.
2. Change the theme from the dropdown list.
3. Customize the font style and size to your preference.

## About

SheeKryptor is a simple but powerful tool for securely encrypting and decrypting files. It aims to provide a safe and easy-to-use solution for managing sensitive data.

- **Version**: v2.1.0
- **Author**: Ahmeed Sheeko
- **Contact**: sheekovic@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.