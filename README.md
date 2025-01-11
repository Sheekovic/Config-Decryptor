# Config Decryptor by SHEEKOVIC

## Description

Config Decryptor is a simple tool built using Python and Tkinter that allows users to decrypt files encrypted with AES (Advanced Encryption Standard) using a 16-byte key and IV (Initialization Vector). This GUI application helps users easily select an encrypted input file and specify where the decrypted output file should be saved.

The tool uses the `cryptography` library for AES decryption and provides a clean and interactive interface for ease of use.

## Features

- **AES Decryption**: Supports decryption of files encrypted using AES in CBC (Cipher Block Chaining) mode.
- **GUI Interface**: Built with Tkinter, allowing users to interact with the application via a responsive window.
- **File Browsing**: Lets users browse and select the input (encrypted) and output (decrypted) files using file dialog boxes.
- **Key and IV Input**: Users can manually enter a 16-byte key and IV for decryption.
- **Responsive Layout**: The application’s layout adapts to window resizing, ensuring a consistent user experience on various screen sizes.

## Requirements

- Python 3.x
- Tkinter (typically included with Python installations)
- `cryptography` library

### Install dependencies

To install the required dependencies, run the following command:

```bash
pip install cryptography
