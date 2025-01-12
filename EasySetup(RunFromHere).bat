@echo off
:: Check if Python is installed
python --version >nul 2>nul

:: If Python is not installed, download and install it
if errorlevel 1 (
    echo Python is not installed. Installing Python...
    
    :: Check operating system
    if /i "%OS%"=="Windows_NT" (
        echo Running on Windows. Downloading Python...

        :: Download and install Python for Windows
        powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.10.0/python-3.10.0.exe -OutFile python_installer.exe"
        start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1
        
        :: Check if Python is installed now
        python --version >nul 2>nul
        if errorlevel 1 (
            echo Python installation failed. Exiting...
            exit /b 1
        )
    ) else (
        echo Unsupported operating system. Exiting...
        exit /b 1
    )
)

:: Print Python version
python --version

:: Install required packages
echo Installing required packages...
echo Installing cryptography library...
pip install cryptography
echo Done installing cryptography.
echo Installing ttkthemes library...
pip install ttkthemes
echo Done installing ttkthemes.

:: Run the SheeKryptor script
echo Running SheeKryptor...
python sheekryptor.py

pause