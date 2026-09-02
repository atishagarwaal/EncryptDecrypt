# EncryptDecrypt

This is a very small .NET console program that shows how to encrypt and decrypt text using AES.

It has a helper class that can turn a plain text string into a secure-looking base64 string (encrypt) and turn that base64 string back into the original text (decrypt).

## Key points
- The program uses AES encryption from System.Security.Cryptography.
- A fixed key is stored in the code (not safe for real use).
- The program generates a random IV for each encryption and stores it at the start of the ciphertext.

## Important security note
This project is an example and is not production-ready. The encryption key is hard-coded in the source (Program.cs). For real use:
- Do NOT store keys in source code.
- Use environment variables or a secret manager.
- Use authenticated encryption and follow cryptography best practices.
