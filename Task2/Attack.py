import base64
import json
import math
import requests
import secrets
import sys

def get_pk(base_url): 
    pk = requests.get(
        f'{base_url}/pk/'
    )
    e = pk.json()['e']
    N = pk.json()['N']

    return e, N

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
        r = secrets.randbelow(n - 2) + 2 
        if math.gcd(r, n) == 1: 
            return r

def modinv(a: int, n: int) -> int:
    return pow(a, -1, n)

def safe_blinded_message(n: int, e: int, target_msg: bytes) -> tuple[int, bytes]:
    k = (n.bit_length() + 7) // 8 
    m = int.from_bytes(target_msg, 'big') 

    while True:
        r = blindingfactor(n) 
        blinded = (m * pow(r, e, n)) % n 
        blinded_bytes = blinded.to_bytes(k, 'big') 
        if any(x in blinded_bytes for x in FORBIDDEN_SUBSTRINGS):
            continue
        return r, blinded_bytes

def main():
    base_url = 'http://localhost:5000'

    e, n = get_pk(base_url)
    n = int(n)
    e = int(e)

    target_msg = b"You got a 12 because you are an excellent student! :)"

    r, candidate_bytes = safe_blinded_message(n, e, target_msg)
    signed = sign_message(base_url, candidate_bytes)
    sig_blinded = int.from_bytes(bytes.fromhex(signed["signature"]), 'big')
    target_sig_int = (sig_blinded * modinv(r, n)) % n
    target_sig_bytes = target_sig_int.to_bytes(len(candidate_bytes), 'big')

    result = forge_cookie(base_url, target_msg, target_sig_bytes)
    print(result)

if __name__ == '__main__':
    main()