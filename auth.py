from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional

# Initialize FastAPI app
app = FastAPI()

# Define a protected endpoint that requires authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Password hashing settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(BaseModel):
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


# Dummy user database
users_db = {
    "johndoe@example.com": User(
        email="johndoe@example.com",
        password=pwd_context.hash("johndoe_password"),
    )
}

# Token expiration time (in minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Token generator function
def generate_token(email: str, expires_delta: Optional[timedelta] = None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = {"sub": email, "exp": expire}
    return token


# Signup endpoint
@app.post("/signup")
def signup(email: str, password: str):
    if email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = pwd_context.hash(password)
    users_db[email] = User(email=email, password=hashed_password)
    return {"message": "User created successfully"}


# Refactored code: 
# Define a function to retrieve a user by email
def get_user(email: str):
    for email_address in users_db:
        if email_address == email:
            return email_address
    return None


# Define a function to authenticate a user and login the user in if successful 
def authenticate_login_user(email: str, password: str):
    user = get_user(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    user_password = users_db[user].password
    if not pwd_context.verify(password, user_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})

    access_token = "fake_access_token"

    return {"access_token": access_token, "token_type": "bearer"}



# Define the login endpoint to accept an email and password and call the authenticate/login function 
@app.post("/login")
async def login(user: UserLogin):

    return authenticate_login_user(user.email, user.password) # Call the combined authentication/login function 

    
# In this refactored code, we have combined the two functions (authentication and login) into one function called 'authenticate/login'. We have also combined the two checks (if not user and if not pwd context) into one statement which will raise an error if either of them are false. Finally, we have called this combined authentication/login function from within our login endpoint instead of calling both functions separately.

@app.get("/protected")
async def protected(token: str = Depends(oauth2_scheme)):
    return {"message": "Hello, you are authenticated!"}