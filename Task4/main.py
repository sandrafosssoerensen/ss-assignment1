import base64
import json
import math
import secrets
import string
from urllib.parse import quote as url_quote
from flask import Flask, request, make_response, redirect, url_for
from secret_data import elgamal_key
from Crypto.Util.number import bytes_to_long, long_to_bytes

app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()


def encrypt(message: bytes) -> bytes:
    """Encrypt a message using our public key."""
    # modulus and private exponent
    p = elgamal_key['_p']
    g = elgamal_key['_g']
    h = elgamal_key['_h']
    # interpret the bytes of the message as an integer stored in big-endian
    # byte order
    m = int.from_bytes(message, 'big')
    if not 0 <= m < p:
        raise ValueError('message too large')
    # compute the encryption
    y = secrets.randbelow(p - 1)
    c1 = pow(g, y, p)
    c2 = m * pow(h, y, p) % p
    # encode the ciphertext into a bytes using big-endian byte order
    ciphertext = c1.to_bytes(math.ceil(p.bit_length() / 8), 'big')
    ciphertext += c2.to_bytes(math.ceil(p.bit_length() / 8), 'big')
    return ciphertext


def decrypt(ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using our private key."""
    # modulus and private exponent
    p = elgamal_key['_p']
    g = elgamal_key['_g']
    h = elgamal_key['_h']
    x = elgamal_key['_x']
    # interpret the bytes of the ciphertext as integers stored
    # in big-endian byte order
    c = bytes.fromhex(ciphertext.hex())
    length = len(c) >> 1
    c1 = int.from_bytes(c[:length], 'big')
    c2 = int.from_bytes(c[length:], 'big')
    if not 0 <= c1 < p or not 0 <= c2 < p:
        raise ValueError('ciphertext too large')
    # decrypt the ciphertext
    s = pow(c1, -x, p)
    m = c2 * s % p
    return m


def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str


def cookie_to_json(base64_as_str: str) -> str:
    """Decode json data stored in a cookie-friendly way using base64."""
    # Check that the input looks like base64 data
    assert all(char in (string.ascii_letters + string.digits + '-_=') for char in base64_as_str), \
            f"input '{base64_as_str}' is no valid base64"
    # decode the base64 data
    json_as_bytes = base64.b64decode(base64_as_str, altchars=b'-_')
    # b64decode returns bytes, we want string -> decode it
    json_as_str = json_as_bytes.decode()
    return json_as_str


@app.route('/')
def index():
    """Redirect to the grade page."""
    return redirect(url_for('grade'))


@app.route('/params/')
def params():
    """Publish our parameters as JSON."""
    p = int(elgamal_key['_p'])
    g = int(elgamal_key['_g'])
    return {'p': p, 'g': g}


@app.route('/grade/')
def grade():
    """Grade student's work and store the grade in a cookie."""
    if 'grade' in request.cookies:  # there is a grade cookie, try to load and verify it
        try:
            # decode the base 64 encoded cookie from the request
            c = cookie_to_json(request.cookies.get('grade'))
            # deserialize the JSON object which we expect in the cookie
            j = json.loads(c)
            # decode the hexadecimal encoded byte strings
            ciphertext = bytes.fromhex(j['ciphertext'])
            msg = long_to_bytes(decrypt(ciphertext))
            # check if the decryption is correct
            if msg != b'You got a 12 because you are an excellent student! :)':
                return '<p>Hm, are you trying to cheat?.</p>'
            return f'<quote>\n{secrets.choice(quotes)}</quote>'
        except Exception as e:
            # if something goes wrong, delete the cookie and try again
            response = redirect(url_for('grade'))
            response.delete_cookie('grade')
            return response
    else:  # the student has not yet been graded, lets do this
        # think very hard, which grade the student deserves
        g = secrets.choice(['-3', '00', '02', '4', '7', '10']) # nobody gets a 12 in my course
        # create the message and UTF-8 encode it into bytes
        msg = f'You get a only get a {g} in Systems Security. I am very disappointed by you.'.encode()
        # encrypt the message
        ciphertext = encrypt(msg)
        # serialize message and ciphertext into a JSON object; for the byte
        # strings we use hexadecimal encoding
        j = json.dumps({'msg': msg.hex(), 'ciphertext': ciphertext.hex()})
        # encode the json data cookie-friendly using base 64
        c = json_to_cookie(j)
        # create a response object
        response = make_response('<p>Here is your grade, and take a cookie!</p>')
        # and store the created JSON object into a cookie
        response.set_cookie('grade', c)
        return response



@app.route('/quote/')
def quote():
    """Show a quote to good students."""
    try:
        # decode the base 64 encoded cookie from the request
        c = cookie_to_json(request.cookies.get('grade'))
        # deserialize the JSON object which we expect in the cookie
        j = json.loads(c)
        # decode the hexadecimal encoded byte strings
        ciphertext = bytes.fromhex(j['ciphertext'])
        msg = long_to_bytes(decrypt(ciphertext))
    except Exception as e:
        return '<p>Hm, are you trying to cheat?.</p>'
    # check if the ciphertext is valid
    if not decrypt(ciphertext):
        return '<p>Hm, are you trying to cheat?.</p>'
    # check if the student is good
    if msg == b'You got a 12 because you are an excellent student! :)':
        return f'<quote>\n{secrets.choice(quotes)}</quote>'
    else:
        return '<p>You should have studied more!</p>'


# students always want me to encrypt their stuff, better automate this
@app.route('/encrypt_random_document_for_students/<data>/')
def encrypt_random_document_for_student(data):
    """Encrypt a given message as long as it does not contain a grade.

    The data is expected in hexadecimal encoding as part of the URL.  E.g.,
    `/encrypt_random_document_for_students/42424242/` returns a ciphertext of the
    string 'BBBB'.
    """
    # hex-decode the data
    msg = bytes.fromhex(data)
    # check if there are any forbidden words in the message
    if any(x.encode() in msg for x in ['grade', '12', 'twelve', 'tolv']):
        return '<p>Haha, nope!</p>'
    try:  # try to encrypt the message
        ciphertext = encrypt(msg)
        # return message and ciphertext hexadecimal encoded in a JSON object
        return {'msg': msg.hex(), 'ciphertext': ciphertext.hex()}
    except Exception as e:  # something went wrong
        return {'error': str(e)}