#
#  Title:  generate_aes_key.py
#  Author: Shuichiro Endo
#

from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes


def generate_key():
    key = get_random_bytes(32)
    return b64encode(key).decode('utf-8')


def generate_iv():
    iv = get_random_bytes(16)
    return b64encode(iv).decode('utf-8')


print("key: " + generate_key())
print("iv : " + generate_iv())

