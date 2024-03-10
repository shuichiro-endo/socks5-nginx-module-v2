#
#  Title:  aes_cbc.py
#  Author: Shuichiro Endo
#

import sys
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(key, iv, data):
    key = b64decode(key)
    iv = b64decode(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_bytes = cipher.encrypt(pad(data, AES.block_size))
    enc = b64encode(enc_bytes).decode('utf-8')
    return enc


def decrypt(key, iv, enc):
    key = b64decode(key)
    iv = b64decode(iv)
    enc_bytes = b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_bytes = unpad(cipher.decrypt(enc_bytes), AES.block_size)
    dec = dec_bytes.decode('utf-8')
    return dec


data = sys.stdin.buffer.read()
key = sys.argv[1]
iv = sys.argv[2]
enc = encrypt(key, iv, data)

print("key: " + key)
print("iv : " + iv)
print("")
print("enc: \n" + enc)

dec = decrypt(key, iv, enc)
print("")
print("dec: \n" + dec)

