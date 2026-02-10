import base64
import json
import math
import requests
import secrets
import sys

def get_pk(base_url): 
    response = requests.get(
        f'{base_url}/pk/'
    )
    return response.json()

def sign_message(base_url, message: bytes):
    data = message.hex()
    url = f"{base_url}/sign_random_document_for_students/{data}/"
    response = requests.get(url)
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        raise RuntimeError(
            f"Non-JSON response from {url} (status {response.status_code}): {response.text}"
        )

def build_grade_cookie(msg_bytes: bytes, sig_bytes: bytes) -> str:
    payload = {
        "msg": msg_bytes.hex(),
        "signature": sig_bytes.hex(),
    }

    json_as_bytes = json.dumps(payload).encode()
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    return base64_as_bytes.decode()

def forge_cookie(base_url, msg_bytes: bytes, sig_bytes: bytes):
    cookie_value = build_grade_cookie(msg_bytes, sig_bytes)
    response = requests.get(f"{base_url}/quote/", cookies={"grade": cookie_value})
    return response.text

FORBIDDEN_SUBSTRINGS = [b'grade', b'12', b'twelve', b'tolv']

def blindingfactor(n: int) -> int:
    """Pick a random r with gcd(r, n) == 1."""
    while True:
        r = secrets.randbelow(n - 2) + 2 # Picks a random number in range [2, n-1]. 0 and 1 are trivial and not useful for blinding.
        if math.gcd(r, n) == 1: # Checks whether r shares a factor with n. If gcd is not 1, then r has no modular inverse, and therefore needs to try again
            return r # r needs to have gcd 1 so it later can be computed r^-1 mod n to unblind the signature

def modinv(a: int, n: int) -> int:
    try:
        return pow(a, -1, n)
    except ValueError:
        raise ValueError("modular inverse does not exist")

# Textbook RSA is deterministic: c = m^e mod n where c = ciphertext, m = message, e = exponent and n = prime number
# Can use the fact that textbook RSA is mallabale.

# Converts target_msg into an integer m
# Pick a random r that is invertible modulo n
# Computes a blinded message m´ = m ⋅ r^e mod n
# Converts m´ back to bytes, then checks those bytes do not contain the forbidden substrings
# This is repeated until it finds a blinded message that passses the filter, and returns both
# r and the blinded bytes
def safe_blinded_message(n: int, e: int, target_msg: bytes) -> tuple[int, bytes]:
    k = (n.bit_length() + 7) // 8 # k is the correct byte length for any value modulo
    m = int.from_bytes(target_msg, 'big') # the first byte is the most significant. Standard for converting message bytes to an integer in RSA.

    while True:
        r = blindingfactor(n) 
        blinded = (m * pow(r, e, n)) % n # m is the integer form of the target message. pow(r, e, n) computes r^e mod n
        blinded_bytes = blinded.to_bytes(k, 'big') # Convert to bytes so it can be sent
        if any(x in blinded_bytes for x in FORBIDDEN_SUBSTRINGS):
            continue
        return r, blinded_bytes

def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:5000'

    pk = get_pk(base_url)
    n = int(pk["N"])
    e = int(pk["e"])
    k = (n.bit_length() + 7) // 8

    target_msg = b"You got a 12 because you are an excellent student! :)"

    r, candidate_bytes = safe_blinded_message(n, e, target_msg)
    signed = sign_message(base_url, candidate_bytes)
    if "error" in signed:
        raise RuntimeError(signed["error"])
    sig_blinded = int.from_bytes(bytes.fromhex(signed["signature"]), 'big')
    target_sig_int = (sig_blinded * modinv(r, n)) % n
    target_sig_bytes = target_sig_int.to_bytes(k, 'big')

    result = forge_cookie(base_url, target_msg, target_sig_bytes)
    print(result)

if __name__ == '__main__':
    main()