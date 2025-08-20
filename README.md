

# AES File Encryption Tool

A simple and secure Python tool that encrypts any file type using military-grade AES-256 encryption with password protection.

## 🔒 How It Works

This tool uses **AES-256 encryption** to protect your files with a password. Here's what happens:

1. **Your password** is converted into a strong 256-bit encryption key using PBKDF2 (100,000 iterations)
2. **Random salt and IV** are generated to make each encryption unique
3. **Your file** is encrypted using AES-256 in CBC mode
4. **The result** is a secure encrypted file that can only be opened with your password

**Security Features:**
- Same file + same password = different encrypted output each time (due to random salt/IV)
- Industry-standard encryption used by governments and military
- Password stretching makes brute force attacks extremely slow

## 📋 Requirements

- **Python 3.8+**
- **Cryptography library**:
```

pip install cryptography

```

## 🚀 How to Run

### Basic Commands

**Encrypt a file:**
```

python aes_file_crypto.py encrypt input_file output_file password

```

**Decrypt a file:**
```

python aes_file_crypto.py decrypt encrypted_file output_file password

```

### Examples

```


# Encrypt any file type

python aes_file_crypto.py encrypt document.pdf document.enc mypassword123
python aes_file_crypto.py encrypt photo.jpg photo.enc secretkey456
python aes_file_crypto.py encrypt song.mp3 song.enc strongpass789

# Decrypt files back to original format

python aes_file_crypto.py decrypt document.enc recovered.pdf mypassword123
python aes_file_crypto.py decrypt photo.enc recovered.jpg secretkey456
python aes_file_crypto.py decrypt song.enc recovered.mp3 strongpass789

```

### Quick Test

```


# Create a test file

echo "This is my secret message" > test.txt

# Encrypt it

python aes_file_crypto.py encrypt test.txt test.enc mypassword

# Decrypt it

python aes_file_crypto.py decrypt test.enc recovered.txt mypassword

# Check the result

cat recovered.txt

```

## ⚠️ Important Notes

- **Use strong passwords** - your file security depends on it
- **Remember your password** - there's no way to recover encrypted files without it
- **Original files are kept safe** - encryption creates new files, doesn't modify originals
- **Works with any file type** - documents, images, videos, audio, etc.

## 🛡️ Security Tips

- Use passwords with 12+ characters including uppercase, lowercase, numbers, and symbols
- Each file should have a unique password
- Store passwords securely (use a password manager)
- Test decryption before deleting original files

---

**⚠️ Warning**: Lost passwords = permanently lost files. This tool provides real security that cannot be bypassed.
```

