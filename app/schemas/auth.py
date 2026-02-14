from pydantic import BaseModel, EmailStr, Field
from typing import Optional


# ─── Request Schemas ─────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    full_name: Optional[str] = None
    organization_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ─── Response Schemas ────────────────────────────────────────────

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    organization_id: Optional[int] = None
    role: str

    class Config:
        from_attributes = True


class RegisterResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    organization_id: Optional[int] = None
    access_token: str
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class MeResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    organization_id: Optional[int] = None
    role: str
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True
