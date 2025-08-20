import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password, salt, key_length=32):
    """Derive a key from password and salt using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path, output_path, password):
    """Encrypt a file using AES encryption"""
    try:
        # Check if input file exists
        if not os.path.exists(input_path):
            print(f"Error: Input file '{input_path}' not found!")
            return False
        
        # Read the input file
        with open(input_path, 'rb') as f:
            data = f.read()
        
        print(f"Original file size: {len(data)} bytes")
        
        # Generate salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Derive key
        key = derive_key(password, salt)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        print(f"Padded data size: {len(padded_data)} bytes")
        
        # Encrypt
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Write salt + iv + encrypted data to output file
        with open(output_path, 'wb') as f:
            f.write(salt + iv + encrypted)
        
        print(f"Encrypted file saved as: {output_path}")
        print(f"Encrypted file size: {len(salt + iv + encrypted)} bytes")
        return True
        
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return False

def decrypt_file(input_path, output_path, password):
    """Decrypt a file using AES decryption"""
    try:
        # Check if input file exists
        if not os.path.exists(input_path):
            print(f"Error: Encrypted file '{input_path}' not found!")
            return False
        
        # Read the encrypted file
        with open(input_path, 'rb') as f:
            raw_data = f.read()
        
        print(f"Encrypted file size: {len(raw_data)} bytes")
        
        # Check minimum file size (salt + iv + at least 1 block)
        if len(raw_data) < 48:  # 16 + 16 + 16 minimum
            print("Error: File too small to be a valid encrypted file!")
            return False
        
        # Extract salt, iv, and encrypted data
        salt = raw_data[:16]
        iv = raw_data[16:32]
        encrypted = raw_data[32:]
        
        print(f"Salt: {len(salt)} bytes, IV: {len(iv)} bytes, Encrypted data: {len(encrypted)} bytes")
        
        # Derive key
        key = derive_key(password, salt)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        print(f"Decrypted padded data size: {len(padded_data)} bytes")
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        print(f"Final decrypted data size: {len(data)} bytes")
        
        # Write decrypted data to output file
        with open(output_path, 'wb') as f:
            f.write(data)
        
        print(f"Decrypted file saved as: {output_path}")
        return True
        
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return False

def main():
    if len(sys.argv) != 5 or sys.argv[1] not in ['encrypt', 'decrypt']:
        print("Usage: python aes_file_crypto.py [encrypt|decrypt] input_file output_file password")
        print("\nExamples:")
        print("  Encrypt: python aes_file_crypto.py encrypt photo.jpg photo.enc mypassword")
        print("  Decrypt: python aes_file_crypto.py decrypt photo.enc photo_dec.jpg mypassword")
        sys.exit(1)
    
    mode, input_file, output_file, password = sys.argv[1:5]
    
    print(f"Mode: {mode}")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print("-" * 50)
    
    if mode == 'encrypt':
        success = encrypt_file(input_file, output_file, password)
    else:
        success = decrypt_file(input_file, output_file, password)
    
    if success:
        print("Operation completed successfully!")
    else:
        print("Operation failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()
