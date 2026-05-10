from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ══════════════════════════════════════════════════════════════════
# CONFIG JWT
# ══════════════════════════════════════════════════════════════════

SECRET_KEY  = "phishguard-secret-key-ensi-2025-change-in-production"
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 heure

# ══════════════════════════════════════════════════════════════════
# UTILISATEURS
# ══════════════════════════════════════════════════════════════════

USERS_DB = {
    "admin": {
        "username":        "admin",
        "full_name":       "Administrateur PhishGuard",
        "role":            "admin",
        "hashed_password": "$2b$12$2GIRbq2w3odxBpVjGCWdOerHPba7e8YQyfKHvSBZ7iIkkfVKtm9jO",
        "disabled":        False,
    },
    "analyst": {
        "username":        "analyst",
        "full_name":       "Analyste Sécurité",
        "role":            "analyst",
        "hashed_password": "$2b$12$LasE/obdr9cD5aUob.Zhku1oAb0ZNKSa3aIZfv/KtwoVUJQY7orvS",
        "disabled":        False,
    },
}

# ══════════════════════════════════════════════════════════════════
# SCHEMAS
# ══════════════════════════════════════════════════════════════════

class Token(BaseModel):
    access_token: str
    token_type:   str
    expires_in:   int
    username:     str
    role:         str


class TokenData(BaseModel):
    username: Optional[str] = None
    role:     Optional[str] = None


class User(BaseModel):
    username:  str
    full_name: Optional[str] = None
    role:      str
    disabled:  Optional[bool] = None


class UserInDB(User):
    hashed_password: str


# ══════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def verify_password(plain_password, hashed_password):
    plain_password = plain_password[:72]  # 🔥 FIX
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user(username: str) -> Optional[UserInDB]:
    if username in USERS_DB:
        return UserInDB(**USERS_DB[username])
    return None


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire    = datetime.utcnow() + (
        expires_delta if expires_delta
        else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ══════════════════════════════════════════════════════════════════
# DÉPENDANCES FASTAPI
# ══════════════════════════════════════════════════════════════════

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role     = payload.get("role")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé"
        )
    return current_user


async def require_admin(
    current_user: User = Depends(get_current_active_user)
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs"
        )
    return current_user

