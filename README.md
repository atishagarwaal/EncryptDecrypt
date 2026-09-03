# EncryptDecrypt

## Overview

EncryptDecrypt is a .NET console application that demonstrates AES encryption and decryption functionality. It provides a simple helper class for converting plain text strings into encrypted base64 strings and vice versa, showcasing fundamental cryptographic operations.

## Description

This project contains a console program built with .NET that implements AES encryption from the `System.Security.Cryptography` namespace. The application includes:

- **Encryption**: Converts plain text into encrypted base64 strings
- **Decryption**: Converts encrypted base64 strings back into original plain text
- **Random IV Generation**: Generates a random Initialization Vector (IV) for each encryption operation and prepends it to the ciphertext for proper decryption

### Key Features
- Uses AES encryption algorithm for secure data transformation
- Demonstrates proper IV handling by storing it with the encrypted data
- Simple and easy-to-understand implementation for educational purposes

### ⚠️ Security Note
This project is intended for educational purposes and is **not production-ready**. Please note:
- The encryption key is hard-coded in the source code (Program.cs)
- **Never store cryptographic keys in source code** in production environments
- Use environment variables or dedicated secret management solutions instead
- Implement authenticated encryption and follow cryptography best practices for real-world applications

## Pre-requisites

- **.NET Framework or .NET Core/5+** installed on your machine
- **Visual Studio** (Community, Professional, or Enterprise) or **Visual Studio Code** with C# extension
- Basic knowledge of C# and console applications
- Administrator privileges (for installation if required)

## Build and Run

### Using Visual Studio

1. **Clone the repository**
   ```bash
   git clone https://github.com/atishagarwaal/EncryptDecrypt.git
   cd EncryptDecrypt
   ```

2. **Open the solution**
   - Open `EncryptDecrypt.sln` in Visual Studio

3. **Build the project**
   - Press `Ctrl + Shift + B` or go to `Build > Build Solution`

4. **Run the application**
   - Press `F5` or click the Start button
   - The console application will execute and display encryption/decryption examples

### Using Command Line (.NET CLI)

1. **Clone the repository**
   ```bash
   git clone https://github.com/atishagarwaal/EncryptDecrypt.git
   cd EncryptDecrypt
   ```

2. **Restore dependencies**
   ```bash
   dotnet restore
   ```

3. **Build the project**
   ```bash
   dotnet build
   ```

4. **Run the application**
   ```bash
   dotnet run
   ```

### Output
The console will display:
- Original plain text
- Encrypted base64 string
- Decrypted text (should match the original)
