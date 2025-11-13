from fastapi import FastAPI, HTTPException, status, Request
from pydantic import BaseModel
import secrets
import time

app = FastAPI()

TOKEN_CACHE = {}
TOKEN_EXPIRE_SECONDS = 30000

class Credentials(BaseModel):
    username: str
    password: str
    
def fetch_from_db():
    username = 'larry'
    password='securepass'
    print('fetching data from db')
    return username, password

def verify_token(token: str):
    if token in TOKEN_CACHE:
        if TOKEN_CACHE[token].get("expiresAt") > time.time():
            return TOKEN_CACHE[token]
        else:
            del TOKEN_CACHE[token]
    return False

@app.post("/login")
def login(credentials: Credentials):
    username, password = fetch_from_db()
    if credentials.username != username or credentials.password != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials"
        )
    token = secrets.token_hex(16)
    TOKEN_CACHE[token] = {
        "username": username,
        "createdAt": time.time(),
        "expiresAt": time.time() + TOKEN_EXPIRE_SECONDS
        }
    
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_EXPIRE_SECONDS}

@app.get("/protected")
def protected(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.split(" ")[1]
    user_details = verify_token(token)
    if not user_details:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    print(user_details)
    return {"message": f"Hello {user_details.get('username')}!"}