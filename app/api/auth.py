from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import User, Organization, AuditLog
from app.schemas.auth import (
    RegisterRequest,
    RegisterResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
)
from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
)
from app.dependencies import get_current_user

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    request: RegisterRequest,
    req: Request,
    db: Session = Depends(get_db),
):
    """Register a new user account.

    If organization_name is provided, creates a new organization
    and sets the user as admin. Otherwise, user is created without an org.
    """
    # Check for existing email
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create organization if name provided
    organization_id = None
    role = "user"

    if request.organization_name:
        org = Organization(
            name=request.organization_name,
            domain=request.email.split("@")[1] if "@" in request.email else None,
        )
        db.add(org)
        db.flush()  # Get the org ID
        organization_id = org.id
        role = "admin"

    # Create user
    user = User(
        email=request.email,
        hashed_password=hash_password(request.password),
        full_name=request.full_name,
        organization_id=organization_id,
        role=role,
    )
    db.add(user)
    db.flush()

    # Generate token
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        organization_id=organization_id,
        role=role,
    )

    # Log registration event
    audit = AuditLog(
        user_id=user.id,
        organization_id=organization_id,
        event_type="registration",
        event_data={"email": user.email},
        ip_address=req.client.host if req.client else None,
        user_agent=req.headers.get("user-agent"),
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    return RegisterResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        organization_id=user.organization_id,
        access_token=access_token,
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    req: Request,
    db: Session = Depends(get_db),
):
    """Authenticate a user and return a JWT token."""
    user = db.query(User).filter(User.email == request.email).first()

    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated",
        )

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        organization_id=user.organization_id,
        role=user.role,
    )

    # Log login event
    audit = AuditLog(
        user_id=user.id,
        organization_id=user.organization_id,
        event_type="login",
        event_data={"email": user.email},
        ip_address=req.client.host if req.client else None,
        user_agent=req.headers.get("user-agent"),
    )
    db.add(audit)
    db.commit()

    return LoginResponse(
        access_token=access_token,
        user={
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "organization_id": user.organization_id,
            "role": user.role,
        },
    )


@router.get("/me", response_model=MeResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get the current authenticated user's info."""
    return current_user
