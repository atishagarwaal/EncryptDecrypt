# EncryptDecrypt

This is a very small .NET console program that shows how to encrypt and decrypt text using AES.

It has a helper class that can turn a plain text string into a secure-looking base64 string (encrypt) and turn that base64 string back into the original text (decrypt).

## Key points (simple)
- Language: C# (.NET 8)
- The program uses AES encryption from System.Security.Cryptography.
- A fixed key is stored in the code (not safe for real use).
- The program generates a random IV for each encryption and stores it at the start of the ciphertext.

## How to run
1. Make sure you have .NET 8 SDK installed: https://dotnet.microsoft.com/
2. From the repository root run:

```bash
cd EncryptDecrypt
dotnet build
dotnet run
```

You should see the program print an "Encrypted" base64 string and the original "Decrypted" text.

## Important security note (short)
This project is an example and is not production-ready. The encryption key is hard-coded in the source (Program.cs). For real use:
- Do NOT store keys in source code.
- Use environment variables or a secret manager.
- Use authenticated encryption and follow cryptography best practices.

## Ideas to improve
- Read the key from an environment variable instead of the code.
- Add command-line options to encrypt/decrypt files or text passed as arguments.
- Add unit tests to check encryption and decryption behavior.

## License
You can add a license file if you want to reuse this code.
