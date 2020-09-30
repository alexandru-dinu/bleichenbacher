import utils


def generate_key(modulus_length):
    prime_length = modulus_length // 2

    # public exponent
    e = 3

    # generate first prime number
    p = 4
    while (p - 1) % e == 0:
        p = utils.generate_prime(prime_length)

    # generate second prime number
    q = p
    while q == p or (q - 1) % e == 0:
        q = utils.generate_prime(prime_length)

    n = p * q
    phi = (p - 1) * (q - 1)

    d = utils.modinv(e, phi)

    public_key = (n, e)
    secret_key = (n, d)

    return public_key, secret_key


def encrypt_integer(public_key, m):
    (n, e) = public_key

    if m > n:
        raise ValueError("Message is to big for current RSA scheme!")

    return pow(m, e, n)


def decrypt_integer(secret_key, c):
    (n, d) = secret_key

    return pow(c, d, n)


def encrypt_string(public_key, message):
    integer = utils.bytes_to_integer(message)
    enc_integer = encrypt_integer(public_key, integer)
    enc_string = utils.integer_to_bytes(enc_integer)

    return enc_string


def decrypt_string(secret_key, ciphertext):
    enc_integer = utils.bytes_to_integer(ciphertext)
    integer = decrypt_integer(secret_key, enc_integer)
    message = utils.integer_to_bytes(integer)

    return message
