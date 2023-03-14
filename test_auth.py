from fastapi.testclient import TestClient
from fastapi import FastAPI
from passlib.context import CryptContext
from auth import User

app = FastAPI()

client = TestClient(app)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Dummy user database
users_db = {
    "johndoe@example.com": User(
        email="johndoe@example.com",
        password=pwd_context.hash("johndoe_password"),
    )
}


def test_login():
    # Create a user for testing
    hashed_password = pwd_context.hash("password")
    user = User(email="test@example.com", password=hashed_password)
    email = user.email
    password = user.password
    users_db[email] = User(email=email, password=password)


    # Test with correct credentials
    response = client.post(
        "/login", data={"username": "test@example.com", "password": "password"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Test with incorrect credentials
    response = client.post(
        "/login", data={"username": "test@example.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert "access_token" not in response.json()
