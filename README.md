# AegisEncrypt
#### "AegisEncrypt: Robust file encryption and decryption for unwavering data protection."
##### AegisEncrypt is a powerful command-line tool designed to provide secure, efficient, and reliable file encryption and decryption using the AES-256-GCM algorithm. This tool ensures your sensitive data remains protected with integrity checks and state-of-the-art cryptographic techniques.

### Features
- AES-256-GCM Encryption: Utilizes the AES-256-GCM mode for both encryption and decryption, offering confidentiality along with integrity and authentication.
- Key Derivation: Employs PBKDF2 for secure key derivation from a passphrase, enhancing the security against brute-force attacks.
- Secure Handling: Ensures all cryptographic keys and sensitive data are securely handled and erased from memory immediately after use.
- Cross-Platform Compatibility: Works seamlessly across multiple platforms including Windows, macOS, and Linux.
  
### Prerequisites
##### Before installing and running AegisEncrypt, ensure your system has the following:

- OpenSSL library (version 1.1.1 or newer)
- GCC compiler (for Linux/macOS) or MinGW (for Windows)

### Installation
To install AegisEncrypt, follow these steps:
## Linux/macOS
Clone the repository or download the source code:
```
git clone https://github.com/gryphonribz/AegisEncrypt.git
cd AegisEncrypt
```

Compile the program:
```
gcc -o AegisEncrypt main.c -lcrypto
```

Install (optional):
```
sudo cp AegisEncrypt /usr/local/bin
```

## Windows
1.Ensure MinGW and OpenSSL are properly installed and configured.
2.Compile using:
```
gcc -o AegisEncrypt.exe main.c -lcrypto -lssl
```

### Usage
Run `AegisEncrypt` from the command line using the following syntax:
```
AegisEncrypt -i <input_file> -o <output_file> -p <passphrase> -e|-d
```

### Parameters:
- `-i <input_file>`: Specify the input file path.
- `-o <output_file>`: Specify the output file path.
- `-p <passphrase>`: Passphrase from which the encryption key is derived.
- `-e`: Encrypt the input file.
- `-d`: Decrypt the input file.

### Examples:
#### Encrypt a file:
```
./AegisEncrypt -i plain.txt -o encrypted.aes -p "mysecurepassphrase" -e
```

#### Decrypt a file:
```
./AegisEncrypt -i encrypted.aes -o decrypted.txt -p "mysecurepassphrase" -d
```

### Contributing
Contributions to AegisEncrypt are welcome! Please fork the repository and submit pull requests with your enhancements, or open issues for bugs or feature requests.

### License
AegisEncrypt is licensed under the GNU GPL V3 License. See the LICENSE file for more details.
