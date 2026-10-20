from fastapi import APIRouter, Request
from pydantic import BaseModel

from backend.services.auth_service import create_access_token
from backend.services.security_service import process_login
from backend.services.user_service import create_user, get_user_role

router = APIRouter()

# =========================
# REQUEST MODELS
# =========================

class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str

# =========================
# REGISTER ROUTE
# =========================

@router.post("/register")
def register(data: RegisterRequest):

    return create_user(
        data.username,
        data.password
    )

# =========================
# LOGIN ROUTE
# =========================

@router.post("/login")
async def login(
    request: Request,
    data: LoginRequest
):

    client_ip = request.client.host

    # =========================
    # PROCESS LOGIN SECURITY
    # =========================

    result = process_login(
        data.username,
        data.password,
        client_ip
    )

    # LOGIN FAILED
    if result["status"] != "success":

        return result

    # =========================
    # GET USER ROLE
    # =========================

    role = get_user_role(
        data.username
    )

    # =========================
    # CREATE JWT TOKEN
    # =========================

    access_token = create_access_token({
        "sub": data.username,
        "role": role
    })

    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "role": role
    }