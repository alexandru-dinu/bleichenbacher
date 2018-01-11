import rsa
import utils

import random
import os
import time

from collections import namedtuple

Interval = namedtuple('Interval', ['lower_bound', 'upper_bound'])

# global RSA key
# only the oracle may use the secret key sk, in this setup
modulus_size = 256
pk, sk = rsa.generate_key(modulus_size)
(n, e) = pk

# modulus size in bytes
k = modulus_size // 8

# global start timer
t_start = time.perf_counter()

# keep track of the oracle calls
global queries
queries = 0

# math.ceil and math.floor don't work for large integers
ceil = lambda a, b: a // b + (a % b > 0)
floor = lambda a, b: a // b


def PKCS1_encode(message, total_bytes):
    """
    Encodes the given message using PKCS1 v1.5 scheme:
    PKCS1(M) = 0x00 | 0x02 | [non-zero padding bytes] | 0x00 | [M]
    length(PKCS1(M)) = total_bytes
    """

    # 11 = 3 constant bytes and at aleast 8 bytes for padding
    if len(message) > total_bytes - 11:
        raise Exception("Message to big for encoding scheme!")
    
    pad_len = total_bytes - 3 - len(message)

    # non-zero padding bytes
    padding = bytes(random.sample(range(1, 256), pad_len))

    encoded = b'\x00\x02' + padding + b'\x00' + message

    return encoded


def PKCS1_decode(encoded):
    """
    Decodes a PKCS1 v1.5 string. 
    Remove constant bytes and random pad until arriving at "\x00".
    The rest is the message.
    """

    encoded = encoded[2:]
    idx = encoded.index(b'\x00')

    message = encoded[idx + 1:]

    return message


def oracle(ciphertext):
    """
    Placeholder for some server which talks RSA PKCS1 v1.5
    It can be used as an oracle, because it tells whether
    the given ciphertext decodes to a valid PKCS1 v1.5 encoding scheme,
    i.e. first 2 bytes of the plaintext == "\x00\x02"
    """
    global queries

    queries += 1
    t = time.perf_counter()
    if queries % 500 == 0:
        print("Query #{} ({} s)".format(queries, round(t - t_start, 3)))

    encoded = rsa.decrypt_string(sk, ciphertext)

    if len(encoded) > k:
        raise Exception("Invalid PKCS1 encoding after decryption!")
    
    if len(encoded) < k:
        zero_pad = b'\x00' * (k - len(encoded))
        encoded = zero_pad + encoded
    
    return encoded[0:2] == b'\x00\x02'


def prepare(message):
    """
    Suppose we intercept a padded ciphertext.
    Our goal is to completely decrypt it, just by using the oracle.
    """
    
    message_encoded = PKCS1_encode(message, k)
    
    ciphertext = rsa.encrypt_string(pk, message_encoded)

    return ciphertext


# Step 2.A.
def find_smallest_s(lower_bound, c):
    """
    Find the smallest s >= lower_bound,
    such that (c * s^e) (mod n) decrypts to a PKCS conforming string
    """
    s = lower_bound

    while True:
        attempt = (c * pow(s, e, n)) % n
        attempt = utils.integer_to_bytes(attempt)

        if oracle(attempt):
            return s

        s += 1


# Step 2.C.
def find_s_in_range(a, b, prev_s, B, c):
    """
    Given the interval [a, b], reduce the search
    only to relevant regions (determined by r)
    and stop when an s value that gives
    a PKCS1 conforming string is found.
    """
    ri = ceil(2 * (b * prev_s - 2 * B), n)

    while True:
        si_lower = ceil(2 * B + ri * n, b)
        si_upper = ceil(3 * B + ri * n, a)

        for si in range(si_lower, si_upper):
            attempt = (c * pow(si, e, n)) % n
            attempt = utils.integer_to_bytes(attempt)

            if oracle(attempt):
                return si
        
        ri += 1


def safe_interval_insert(M_new, interval):
    """
    Deal with interval overlaps when adding a new one to the list
    """

    for i, (a, b) in enumerate(M_new):
        
        # overlap found, construct the larger interval
        if (b >= interval.lower_bound) and (a <= interval.upper_bound):
            lb = min(a, interval.lower_bound)
            ub = max(b, interval.upper_bound)

            M_new[i] = Interval(lb, ub)
            return M_new
    
    # no overlaps found, just insert the new interval
    M_new.append(interval)

    return M_new


# Step 3.
def update_intervals(M, s, B):
    """
    After found the s value, compute the new list of intervals
    """

    M_new = []

    for a, b in M:
        r_lower = ceil(a * s - 3 * B + 1,  n)
        r_upper = ceil(b * s - 2 * B,  n)

        for r in range(r_lower, r_upper):
            lower_bound = max(a, ceil(2 * B + r * n,  s))
            upper_bound = min(b, floor(3 * B - 1 + r * n, s))

            interval = Interval(lower_bound, upper_bound)

            M_new = safe_interval_insert(M_new, interval)

    M.clear()

    return M_new


def bleichenbacher(ciphertext):
    """
    Perform Bleichenbacher attack as described in his paper.
    """

    # Step 1. is only needed when the ciphertext is
    # not PKCS1 conforming

    # integer value of ciphertext
    c = utils.bytes_to_integer(ciphertext)

    B = 2 ** (8 * (k - 2))

    M = [Interval(2 * B, 3 * B - 1)]

    # Step 2.A.
    s = find_smallest_s(ceil(n, 3 * B), c)

    M = update_intervals(M, s, B)

    while True:
        # Step 2.B.
        if len(M) >= 2:
            s = find_smallest_s(s + 1, c)

        # Step 2.C.
        elif len(M) == 1:
            a, b = M[0]

            # Step 4.
            if a == b:
                return utils.integer_to_bytes(a % n)
            
            s = find_s_in_range(a, b, s, B, c)
            
        M = update_intervals(M, s, B)


def main():
    global queries
    
    simulations = False

    if simulations:
        total = []

        for i in range(100):
            message = bytes(os.urandom(11))

            ciphertext = prepare(message)
            decrypted = bleichenbacher(ciphertext)
            decrypted = PKCS1_decode(decrypted)

            assert decrypted == message

            total.append(queries)
            print(i)

            queries = 0

        print(total)
    else:
        message = b'1337h4x0rz'
        ciphertext = prepare(message)
        decrypted = bleichenbacher(ciphertext)
        decrypted = PKCS1_decode(decrypted)

        assert decrypted == message

        print("----------")
        print("queries:\t{}".format(queries))
        print("message:\t{}".format(message))
        print("decrypt:\t{}".format(decrypted))

        
def run_tests(m):
    """
    Small sanity test suite
    """
    menc = PKCS1_encode(m, k)
    
    print("1. (un)pad:", PKCS1_decode(menc) == m)
    
    m1 = rsa.decrypt_string(sk, rsa.encrypt_string(pk, m))
    print("2. rsa w/o pad:", m == m1)

    m2 = PKCS1_decode(rsa.decrypt_string(sk, rsa.encrypt_string(pk, menc)))
    print("3. rsa w/ pad:", m == m2)

    m3 = oracle(rsa.encrypt_string(pk, menc)) == True
    print("4. oracle well-formed:", m3)

    m4 = oracle(rsa.encrypt_string(pk, m)) == False
    print("5. oracle not well-formed", m4)



if __name__ == '__main__':
    main()
   