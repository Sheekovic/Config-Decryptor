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
```

## Usage

1. **Launch the Application**:
    - Run the Python script `main.py` to start the application.
  
2. **Select Input File**:
    - Click the **Browse** button next to the **Input File** field to select the encrypted file you want to decrypt.

3. **Select Output File**:
    - Click the **Browse** button next to the **Output File** field to specify where the decrypted file should be saved.

4. **Enter Key and IV**:
    - Input a 16-byte key and a 16-byte IV (both should be exactly 16 bytes long).

5. **Start Decryption**:
    - Click the **Decrypt** button to begin the decryption process.

6. **Completion**:
    - Upon successful decryption, a success message will appear, and the output file will be saved at the specified location.
    - If any errors occur, an error message will display.

## How It Works

- **AES Decryption**: 
    - The tool uses the `cryptography` library to perform AES decryption in CBC mode.
    - The user must provide a 16-byte key and 16-byte IV for the decryption process.
    - If the inputs are valid, the encrypted file is read, decrypted, and saved as the output file.

- **File Selection**: 
    - Users can easily browse their file system to select the encrypted file to decrypt and where to save the decrypted file.

- **Responsive UI**: 
    - The window and elements adjust dynamically when resized to maintain a user-friendly layout.

## Screenshots

*Include any screenshots of the application here.*

## License

This project is open source and available under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## Contact

- **Creator**: SHEEKOVIC
- **GitHub**: [GitHub Profile](https://github.com/Sheekovic)

Feel free to reach out if you have any questions or suggestions!