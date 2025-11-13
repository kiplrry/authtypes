from fastapi import FastAPI, HTTPException, status, Request
import base64

app = FastAPI()
def fetch_from_db():
    username = 'larry'
    password='securepass'
    print('fetching data from db')
    return username, password

@app.get("/")
def read_root(request: Request): 
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Basic"}, #tells the browser to prompt for credentials
        )
    
    #splitting and decoding the auth
    encoded_creds = auth.split(" ")[1]
    decoded = base64.b64decode(encoded_creds).decode("utf-8")
    username, password = decoded.split(':')

    _username, _pass = fetch_from_db()

    if username != _username or password != _pass:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )
    


    return {"message": f"Hello, {username}!\n"}

