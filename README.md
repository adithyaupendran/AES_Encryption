
## 🔧 How It Works

### 1. Encryption Process
1. **Key Derivation**: Your password is converted to a 256-bit AES key using PBKDF2
2. **Random Generation**: Unique salt and IV are generated for each encryption
3. **Padding**: Data is padded to AES block size (16 bytes) using PKCS7
4. **Encryption**: Data is encrypted using AES-256 in CBC mode
5. **Packaging**: Salt + IV + encrypted data are combined

### 2. Steganography Process
1. **Image Loading**: Cover image is loaded and converted to RGB
2. **Data Encoding**: Encrypted data is encoded to Base64 for safe handling
3. **LSB Insertion**: Each bit of data is hidden in the least significant bit of image pixels
4. **Delimiter**: Special marker indicates end of hidden data
5. **Image Saving**: Modified image is saved as PNG to preserve hidden data

### 3. Security Features
- **Double Protection**: Steganography hides existence, encryption protects content
- **Unique Encryption**: Same file + password = different output each time
- **Key Stretching**: 100,000 PBKDF2 iterations slow down brute force attacks
- **Industry Standards**: Uses AES-256, the same encryption used by governments

## ⚠️ Important Notes

### File Format Requirements
- **Cover Images**: JPG, PNG, BMP (will be saved as PNG)
- **Hidden Files**: Any file type supported
- **Output**: Always saved as PNG to prevent compression artifacts

### Security Considerations
- **Password Strength**: Use strong, unique passwords
- **File Size**: Cover image must be large enough to hold encrypted data
- **Detection**: While steganography hides data, sophisticated analysis might detect it
- **Backup**: Keep secure backups of important encrypted files

### Limitations
- Large files require large cover images
- PNG output files may be larger than original cover images
- Detection possible with advanced steganalysis tools

## 🧪 Testing

### Quick Test
