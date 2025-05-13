#!/usr/bin/env python3
import os
import base64
import argparse
import logging
import sqlite3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
try:
    from sqlcipher3 import dbapi2 as sqlcipher
except ImportError:
    sqlcipher = None

# Setup logging to both console and results.txt
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('results.txt', mode='w'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
AES_KEY = b"obdswhatisthekey"  # 16 bytes for AES-128
SQLCIPHER_KEY = "DCCF97A6-B286-4FFF-88E3-29252E983BAC"
IV_LENGTH = 16
HEADER_LENGTH = 24  # 8 bytes fixed header + 16 bytes IV
LIB_FILE = "EN_DIAG.lib"  # Default .lib file in project root
OUTPUT_DB = "decrypted.db"

def validate_file(file_path):
    """Validate if the input file exists and is readable."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File {file_path} does not exist.")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File {file_path} is not readable.")
    logger.info(f"Validated file: {file_path}")
    return True

def extract_iv(data):
    """Extract IV from .lib file header (bytes 9–24)."""
    if len(data) < HEADER_LENGTH:
        raise ValueError("File too small to contain header.")
    iv = data[8:8 + IV_LENGTH]
    if len(iv) != IV_LENGTH:
        raise ValueError(f"Expected IV length {IV_LENGTH}, got {len(iv)}.")
    logger.info(f"Extracted IV: {iv.hex()}")
    return iv

def decrypt_data(encrypted_data, key, iv):
    """Decrypt AES-128 CBC data with PKCS#7 padding."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(padded_data, AES.block_size, style='pkcs7')
        logger.info("AES decryption successful")
        return decrypted_data
    except ValueError as e:
        logger.error(f"Decryption failed: {e}")
        raise

def encrypt_data(plain_data, key, iv):
    """Encrypt data with AES-128 CBC and PKCS#7 padding."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_data = pad(plain_data, AES.block_size, style='pkcs7')
        encrypted_data = cipher.encrypt(padded_data)
        logger.info("AES encryption successful")
        return encrypted_data
    except ValueError as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decode_base64(data):
    """Decode Base64-encoded data."""
    try:
        decoded = base64.b64decode(data)
        logger.info("Base64 decoding successful")
        return decoded
    except Exception as e:
        logger.error(f"Base64 decoding failed: {e}")
        raise

def encode_base64(data):
    """Encode data to Base64."""
    encoded = base64.b64encode(data)
    logger.info("Base64 encoding successful")
    return encoded

def decrypt_lib_file(input_path, output_path):
    """Decrypt a .lib file and output a SQLite database."""
    logger.info(f"Starting decryption of {input_path}")
    validate_file(input_path)

    # Read .lib file
    with open(input_path, 'rb') as f:
        data = f.read()

    # Extract IV and encrypted data
    iv = extract_iv(data)
    encrypted_data = data[HEADER_LENGTH:]

    # Decrypt AES
    decrypted_data = decrypt_data(encrypted_data, AES_KEY, iv)

    # Write temporary decrypted file
    temp_path = "temp_decrypted.db"
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    logger.info(f"Temporary decrypted file written: {temp_path}")

    # Apply SQLCipher key
    if sqlcipher is None:
        logger.error("sqlcipher3 module not installed. Cannot process SQLCipher database.")
        raise ImportError("Please install sqlcipher3: pip install sqlcipher3")
    
    try:
        conn = sqlcipher.connect(temp_path)
        conn.execute(f"PRAGMA key = '{SQLCIPHER_KEY}';")
        # Test query to validate database
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        logger.info(f"Database tables: {tables}")
        conn.commit()

        # Export to standard SQLite
        with sqlite3.connect(output_path) as out_conn:
            for line in conn.iterdump():
                out_conn.execute(line)
        logger.info(f"Decrypted SQLite database saved to: {output_path}")
    except Exception as e:
        logger.error(f"SQLCipher processing failed: {e}")
        raise
    finally:
        conn.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)
            logger.info(f"Temporary file removed: {temp_path}")

def decrypt_text(encrypted_text):
    """Decrypt Base64-encoded encrypted text."""
    logger.info("Decrypting text input")
    encrypted_data = decode_base64(encrypted_text.encode())
    if len(encrypted_data) < IV_LENGTH:
        raise ValueError("Encrypted text too short to contain IV.")
    iv = encrypted_data[:IV_LENGTH]
    encrypted_data = encrypted_data[IV_LENGTH:]
    decrypted_data = decrypt_data(encrypted_data, AES_KEY, iv)
    result = decrypted_data.decode()
    logger.info(f"Decrypted text: {result}")
    return result

def encrypt_text(plain_text, iv):
    """Encrypt text with AES-128 CBC and return Base64-encoded result."""
    logger.info("Encrypting text input")
    plain_data = plain_text.encode()
    encrypted_data = encrypt_data(plain_data, AES_KEY, iv)
    result = iv + encrypted_data
    encoded_result = encode_base64(result).decode()
    logger.info(f"Encrypted text (Base64): {encoded_result}")
    return encoded_result

def main():
    parser = argparse.ArgumentParser(description="Decrypt/Encrypt .lib files or text")
    parser.add_argument('--decrypt-lib', help="Path to encrypted .lib file", default=LIB_FILE)
    parser.add_argument('--output', help="Output SQLite database path", default=OUTPUT_DB)
    parser.add_argument('--decrypt-text', help="Base64-encoded encrypted text")
    parser.add_argument('--encrypt-text', help="Plain text to encrypt")
    parser.add_argument('--iv', help="IV for encryption (16 bytes, hex)", default="00000000000000000000000000000000")
    args = parser.parse_args()

    logger.info("Starting application")
    try:
        if args.decrypt_lib:
            decrypt_lib_file(args.decrypt_lib, args.output)
        elif args.decrypt_text:
            result = decrypt_text(args.decrypt_text)
            print(f"Decrypted text: {result}")
        elif args.encrypt_text:
            iv = bytes.fromhex(args.iv)
            if len(iv) != IV_LENGTH:
                raise ValueError("IV must be 16 bytes.")
            result = encrypt_text(args.encrypt_text, iv)
            print(f"Encrypted text (Base64): {result}")
        else:
            # Default action: Decrypt EN_DIAG.lib
            decrypt_lib_file(LIB_FILE, OUTPUT_DB)
    except Exception as e:
        logger.error(f"Application failed: {e}")
        print(f"Error: {e}. Check results.txt for details.")
        exit(1)
    logger.info("Application completed successfully")

if __name__ == "__main__":
    main()