import base64
import json
import hmac
import hashlib
import time

EXPIRY_TIME = 60
SECRET_KEY='superdupersecretkey'

def base64url_encode(data: bytes)->str:
    '''JWT encoding does not use the padding so we get rid of it'''
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def base64url_decode(data: str)-> bytes:
    '''not necessary to add padding but in strict decoders its needed
        padding ensures the string is divisible by 4
    '''
    padding = '=' * (4 - (len(data) % 4)) 
    return base64.urlsafe_b64decode((data + padding))

def create_jwt(payload):
    header = {'alg': "HS256", "type": "JWT"}

    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    msg = f'{header_b64}.{payload_b64}'.encode()


    signature = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest() #signature is created 

    signature_b64 = base64url_encode(signature)
    return f'{header_b64}.{payload_b64}.{signature_b64}'

def jwt_verify(token: str)-> bool:
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
    except ValueError:
        raise ValueError("Invalid token format")
    
    msg = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
    expected_signature = base64url_encode(signature)

    return hmac.compare_digest(expected_signature, signature_b64)


payload = {
    'user_id': 1212,
    'email': 'larry@gmail.com',
    'exp': time.time() + EXPIRY_TIME
}

jwt = create_jwt(payload)
print(jwt)
print(jwt_verify(jwt))