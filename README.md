# PassGhost Browsers Passwords Decryptor
```
 ____                ____ _               _
|  _ \ __ _ ___ ___ / ___| |__   ___  ___| |_
| |_) / _` / __/ __| |  _| '_ \ / _ \/ __| __|
|  __/ (_| \__ \__ \ |_| | | | | (_) \__ \ |_
|_|   \__,_|___/___/\____|_| |_|\___/|___/\__|
     Firefox & Chrome Password Decryptor
```
A simple set of tools to decrypt saved passwords from **Mozilla Firefox** and **Google Chrome** browsers on Windows.

---

## Overview

This repository contains two console applications written in C#:

- **PassGhost**  
  Extracts and decrypts saved passwords from Firefox and Chrome browsers and displays them in the console.  
  Supports exporting the results to **plaintext** or **JSON** files, optionally encrypted with a password.

- **PassGhostDecryptor**  
  Decrypts the encrypted export files created by PassGhost.  
  Use this to retrieve plaintext password data from encrypted output files.

---

## Features

- Extract and decrypt passwords saved in Firefox profiles using `nss3.dll`
- Extract and decrypt Chrome passwords using DPAPI and AES-GCM master key
- Export results to text or JSON files
- Optional encryption of exported files with a password (using AES)
- Decrypt encrypted export files to recover plaintext data

---

## Requirements

- **Windows OS**  
  (The decryption relies on Windows DPAPI for Chrome and Windows-compatible NSS libraries for Firefox.)

- **.NET 6.0 SDK or later**  
  To build and run the console applications.

- **Firefox's `nss3.dll` and related NSS libraries**  
  Typically found in the Firefox installation directory. Ensure the `nss3.dll` is accessible (e.g., copied to the executable folder or system PATH).

- **SQLite**  
  The projects use `System.Data.SQLite` NuGet package to read Chrome's `Login Data` SQLite database.

---

## Setup

1. **Build the solution** in Visual Studio or via CLI:  dotnet build
2. **Locate executables** after build:  
- `PassGhost\bin\Debug\net6.0\PassGhost.exe`  
- `PassGhostDecryptor\bin\Debug\net6.0\PassGhostDecryptor.exe`

3. **Make sure `nss3.dll` is available** in the same folder as the Firefox profile or in your system PATH.

---

## Usage

### PassGhost (Main Password Extractor)

PassGhost.exe [options]

**Options:**

- `--export-txt <filename>`  
  Export passwords to a plaintext `.txt` file.

- `--export-json <filename>`  
  Export passwords to a formatted `.json` file.

- `--encrypt`  
  Encrypt the exported file using a fixed password prompt (or passphrase defined in code).  
  (Currently the password is hardcoded — future improvements can add prompt or parameter input.)

- `--help` or `-h`  
  Show help information.

---

### PassGhostDecryptor (Decrypt Encrypted Export Files)

PassGhostDecryptor.exe <encrypted_file>


- Reads an encrypted `.txt` or `.json` file produced by PassGhost with `--encrypt`.
- Outputs the decrypted plaintext content to the console.

---

## Where to Find Password Data

- **Firefox Profiles**:  
  Located under:  
  `%APPDATA%\Mozilla\Firefox\Profiles\`  
  (The tool detects all profiles containing a `logins.json` file.)

- **Chrome Profile**:  
  Located under:  
  `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`  
  (The tool reads the `Login Data` SQLite database.)

---

## Notes

- This tool must be run by the **same Windows user account** that saved the passwords, due to DPAPI encryption tied to the user profile.
- Firefox decryption depends on correct loading of NSS libraries and profile initialization.
- Handle the exported files carefully, especially if unencrypted, as they contain sensitive data.
- The encryption password in the current implementation is hardcoded as `"secret_key"`. Modify the source code to change this or add user input if desired.

---

## License

This project is provided as-is for educational and personal use.

---

## Disclaimer

Use these tools responsibly and only on machines and accounts you own or have explicit permission to audit. Unauthorized access to saved passwords may violate privacy and legal regulations.

---

## Contact

For issues or feature requests, please open an issue on this repository.
