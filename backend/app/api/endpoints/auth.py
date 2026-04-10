from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

# For demonstration purposes, using a simple in-memory store
# In production, use a proper user database
users = {
    "admin": {
        "username": "admin",
        "password": "admin123",  # In production, use hashed passwords
        "role": "admin"
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

@router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    # In production, generate a proper JWT token
    return {"access_token": "fake-token", "token_type": "bearer"}

@router.get("/me", response_model=User)
def get_current_user():
    # In production, validate the token and get the user
    return {"username": "admin", "role": "admin"}
