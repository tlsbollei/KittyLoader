#!/usr/bin/env python3
import argparse
import os
import hashlib
from Crypto.Cipher import ChaCha20

def encrypt_shellcode(shellcode_file, output_file, key=None):    
    with open(shellcode_file, 'rb') as f:
        shellcode = f.read()
    if key is None:
        key = os.urandom(32)
    
    nonce = os.urandom(12)
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_data = cipher.encrypt(shellcode)
    
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"[+] Shellcode encrypted successfully")
    print(f"[+] Key: {key.hex()}")
    print(f"[+] Nonce: {nonce.hex()}")
    print(f"[+] Output: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KittyLoader Shellcode Encryptor")
    parser.add_argument("input", help="Input shellcode file")
    parser.add_argument("output", help="Output encrypted file")
    parser.add_argument("--key", help="Encryption key (hex)", default=None)
    
    args = parser.parse_args()
    
    key = None
    if args.key:
        key = bytes.fromhex(args.key)
    
    encrypt_shellcode(args.input, args.output, key)
