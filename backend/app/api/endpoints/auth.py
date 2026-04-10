from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import jwt
import datetime
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 密码承载令牌
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# 密钥，在生产环境中应该从环境变量或安全的配置中获取
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# For demonstration purposes, using a simple in-memory store
# In production, use a proper user database
users = {
    "admin": {
        "username": "admin",
        "password": pwd_context.hash("admin123"),  # 哈希密码
        "role": "admin"
    },
    "user": {
        "username": "user",
        "password": pwd_context.hash("user123"),  # 哈希密码
        "role": "user"
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

class UserInDB(User):
    password: str

def verify_password(plain_password, hashed_password):
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """获取密码哈希"""
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    """验证用户"""
    user = users.get(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    """创建访问令牌"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """获取当前用户"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = users.get(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user = Depends(get_current_user)):
    """获取当前活跃用户"""
    return current_user

async def get_current_admin_user(current_user = Depends(get_current_user)):
    """获取当前管理员用户"""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

@router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=User)
def get_current_user_info(current_user = Depends(get_current_active_user)):
    """获取当前用户信息"""
    return {"username": current_user["username"], "role": current_user["role"]}

@router.post("/register")
def register(username: str, password: str, role: str = "user"):
    """注册新用户"""
    if username in users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    users[username] = {
        "username": username,
        "password": get_password_hash(password),
        "role": role
    }
    return {"message": "User registered successfully"}

@router.get("/users")
def get_users(current_user = Depends(get_current_admin_user)):
    """获取所有用户（仅管理员）"""
    return [{
        "username": user["username"],
        "role": user["role"]
    } for user in users.values()]
