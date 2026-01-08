🔐 File Encryption Tool (Learning Project)
======================================

Overview
--------

This is a small Python project created to learn practical cryptography by building a real file encryption and decryption tool using the cryptography library. (`cryptography` docs: https://cryptography.io/)
The goal is not to replace existing tools, but to understand what happens under the hood and feel comfortable using modern crypto primitives.

What the script does
--------------------

Encrypts a file using symmetric encryption
Decrypts the file back to its original form
Supports:
A random generated key stored in a file
A password-based key derived using PBKDF2 (`PBKDF2HMAC` docs: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)

Cryptography concepts learned
-----------------------------

While building this project, I understood and applied:
Symmetric encryption (same key for encrypt/decrypt)
AES-based encryption (used internally by Fernet)
CBC-like behavior with randomness (each encryption produces different output)
Key derivation using PBKDF2 (password → cryptographic key)
Authentication to detect modified or corrupted data
Correct handling of binary files using rb / wb

How encryption works (high level)
---------------------------------

A secure key is created (random or derived from a password)
Data is encrypted using AES
Randomness is added so identical files never produce the same ciphertext
Integrity is verified during decryption to prevent tampering

Relation to OpenSSL
-------------------

This functionality already exists in tools like OpenSSL (OpenSSL `enc` docs: https://leancrew.com/all-this/man/man1/openssl-enc.html), for example: [web:21]
```
openssl enc -aes-256-cbc -in file -out file.enc
```
```
openssl enc -aes-256-cbc -d -in file.enc -out file.dec
```

This project reimplements the idea for learning purposes, to understand how encryption, keys, and file handling really work.
