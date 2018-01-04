"""
PKCS1(M) = 0x00 | 0x02 | [non-zero padding bytes] | 0x00 | [M]
"""

import rsa
import utils
import random

import os

pk, sk = rsa.generate_key(256)

def PKCS1(message, total_length):
    if len(message) > total_length - 11:
        raise Exception("Message to big for encoding scheme!")
    
    pad_len = total_length - 3 - len(message)

    # non-zero padding bytes
    padding = bytes(random.sample(range(1, 256), pad_len))

    encoded = b'\x00\x02' + padding + b'\x00' + message

    return encoded

def unpad(encoded):
    encoded = encoded[2:]

    idx = encoded.index(b'\x00')

    message = encoded[idx + 1:]

    return message

# oracle has access to the secret key
def oracle(ciphertext):
    encoded = rsa.decrypt_string(sk, ciphertext)

    # modulus length in bytes
    k = 256 // 8

    if len(encoded) > k:
        raise Exception("Invalid PKCS1 encoding after decryption!")
    
    if len(encoded) < k:
        zero_pad = b'\x00' * (k - len(encoded))
        encoded = zero_pad + encoded
    
    return encoded[0:2] == b'\x00\x02'



def run_tests(m):
    # modulus length in bytes
    k = 256 // 8

    mpad = PKCS1(m, k)
    
    print("1. (un)pad:", unpad(mpad) == m)
    
    m1 = rsa.decrypt_string(sk, rsa.encrypt_string(pk, m))
    print("2. rsa w/o pad:", m == m1)

    m2 = unpad(rsa.decrypt_string(sk, rsa.encrypt_string(pk, mpad)))
    print("3. rsa w/ pad:", m == m2)

    m3 = oracle(rsa.encrypt_string(pk, mpad)) == True
    print("4. oracle well-formed:", m3)

    m4 = oracle(rsa.encrypt_string(pk, m)) == False
    print("5. oracle not well-formed", m4)


if __name__ == '__main__':
    (n, e) = pk
    (_, d) = sk


    ### TEST
    run_tests(b'Hello, World!')
    


   