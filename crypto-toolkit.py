import argparse
import base64
import binascii
import requests
from sympy import mod_inverse, gcd, isprime
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import itertools

# Utility functions
def hex_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)

def bytes_to_hex(byte_data):
    return binascii.hexlify(byte_data).decode()

def base64_to_bytes(base64_string):
    return base64.b64decode(base64_string)

def bytes_to_base64(byte_data):
    return base64.b64encode(byte_data).decode()

def hash_md5(data):
    return hashlib.md5(data).hexdigest()

def hash_sha256(data):
    return hashlib.sha256(data).hexdigest()

def hash_sha1(data):
    return hashlib.sha1(data).hexdigest()

# Caesar Cipher
def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            plaintext += char
    return plaintext

# XOR Cipher
def xor_decrypt(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def xor_brute_force(ciphertext):
    for key in range(256):
        try:
            plaintext = bytes([b ^ key for b in ciphertext]).decode()
            print(f"Key: {key}, Plaintext: {plaintext}")
        except UnicodeDecodeError:
            continue

# RSA Functions
def rsa_decrypt(n, e, d, ciphertext):
    cipher_int = bytes_to_long(ciphertext)
    plain_int = pow(cipher_int, d, n)
    return long_to_bytes(plain_int)

def rsa_factorize(n):
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

def rsa_generate_keys(bit_size):
    p = getPrime(bit_size // 2)
    q = getPrime(bit_size // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return {
        "public_key": (n, e),
        "private_key": (n, d),
        "p": p,
        "q": q
    }

# AES Functions
def aes_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

# Vigenere Cipher
def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    for c, k in zip(ciphertext, key):
        if c.isalpha():
            offset = 65 if c.isupper() else 97
            plaintext += chr((ord(c) - offset - (ord(k) - offset)) % 26 + offset)
        else:
            plaintext += c
    return plaintext

# Frequency Analysis
def frequency_analysis(text):
    freq = {}
    for char in text:
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    return {k: v / len(text) for k, v in sorted(freq.items(), key=lambda item: -item[1])}

# Modular Arithmetic
def solve_modular_equation(a, b, n):
    try:
        x = (mod_inverse(a, n) * b) % n
        return x
    except ValueError:
        return "No solution"

# Online API Integration
def query_pwned_passwords(password):
    sha1_hash = hash_sha1(password.encode()).upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return f"Password found {count} times!"
    return "Password not found."

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description="Advanced Cryptography Toolkit")
    parser.add_argument("--mode", required=True, choices=[
        "caesar", "xor", "xor-brute", "rsa", "aes", "vigenere", "base64", "hex", "hash-md5", "hash-sha1", "hash-sha256", "freq-analysis", "modular", "pwned-passwords"
    ], help="Choose the operation mode")
    parser.add_argument("--input", required=True, help="Input data")
    parser.add_argument("--key", help="Key for decryption/encryption")
    parser.add_argument("--shift", type=int, help="Shift value for Caesar cipher")
    parser.add_argument("--n", type=int, help="RSA modulus n")
    parser.add_argument("--e", type=int, help="RSA public exponent e")
    parser.add_argument("--d", type=int, help="RSA private exponent d")
    parser.add_argument("--iv", help="Initialization vector for AES (hex-encoded)")
    parser.add_argument("--a", type=int, help="Coefficient a in modular equation")
    parser.add_argument("--b", type=int, help="Coefficient b in modular equation")
    parser.add_argument("--mod", type=int, help="Modulus in modular equation")
    args = parser.parse_args()

    if args.mode == "caesar":
        if not args.shift:
            print("Shift value is required for Caesar cipher")
            return
        print("Decrypted text:", caesar_decrypt(args.input, args.shift))

    elif args.mode == "xor":
        if not args.key:
            print("Key is required for XOR decryption")
            return
        ciphertext = hex_to_bytes(args.input)
        key = int(args.key)
        print("Decrypted text:", xor_decrypt(ciphertext, key).decode(errors='ignore'))

    elif args.mode == "xor-brute":
        ciphertext = hex_to_bytes(args.input)
        xor_brute_force(ciphertext)

    elif args.mode == "rsa":
        if not all([args.n, args.e, args.d]):
            print("n, e, and d values are required for RSA decryption")
            return
        ciphertext = hex_to_bytes(args.input)
        print("Decrypted text:", rsa_decrypt(args.n, args.e, args.d, ciphertext).decode(errors='ignore'))

    elif args.mode == "aes":
        if not all([args.key, args.iv]):
            print("Key and IV are required for AES decryption")
            return
        key = hex_to_bytes(args.key)
        iv = hex_to_bytes(args.iv)
        ciphertext = hex_to_bytes(args.input)
        print("Decrypted text:", aes_decrypt(key, iv, ciphertext).decode(errors='ignore'))

    elif args.mode == "vigenere":
        if not args.key:
            print("Key is required for Vigenere cipher")
            return
        print("Decrypted text:", vigenere_decrypt(args.input, args.key))

    elif args.mode == "freq-analysis":
        print("Frequency analysis:", frequency_analysis(args.input))

    elif args.mode == "base64":
        print("Decoded text:", base64_to_bytes(args.input).decode(errors='ignore'))

    elif args.mode == "hex":
        print("Decoded text:", hex_to_bytes(args.input).decode(errors='ignore'))

    elif args.mode == "hash-md5":
        print("MD5 hash:", hash_md5(args.input.encode()))

    elif args.mode == "hash-sha1":
        print("SHA1 hash:", hash_sha1(args.input.encode()))

    elif args.mode == "hash-sha256":
        print("SHA256 hash:", hash_sha256(args.input.encode()))

    elif args.mode == "modular":
        if not all([args.a, args.b, args.mod]):
            print("a, b, and mod values are required for modular equation")
            return
        print("Solution to modular equation:", solve_modular_equation(args.a, args.b, args.mod))

    elif args.mode == "pwned-passwords":
        print(query_pwned_passwords(args.input))

if __name__ == "__main__":
    main()
