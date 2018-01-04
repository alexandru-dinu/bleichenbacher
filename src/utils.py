import random
import gmpy2

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a, a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

def generate_prime(bit_length):
        while True:
            lb = 2 ** (bit_length - 1)
            ub = (2 ** bit_length) - 1
            candidate = random.randint(lb, ub)
            if gmpy2.is_prime(candidate):
                return candidate

def bytes_to_integer(bytes_obj):
    return int.from_bytes(bytes_obj, byteorder='big')

def integer_to_bytes(integer):
    k = integer.bit_length()

    # adjust number of bytes
    bytes_length = k // 8 + (k % 8 > 0)

    bytes_obj = integer.to_bytes(bytes_length, byteorder='big')

    return bytes_obj
