from fastapi import FastAPI, Depends

from backend.routes.auth_routes import router as auth_router
from backend.routes.admin_routes import router as admin_router


from backend.services.auth_service import (
    verify_token,
    verify_admin
)

from backend.services.user_service import create_users_table

from backend.init_db import init_db

# =========================
# FASTAPI APP
# =========================

app = FastAPI(
    title="AutoSecCloud API",
    version="1.0.0"
)

# =========================
# CREATE DATABASE TABLES
# =========================

create_users_table()

init_db()

# =========================
# REGISTER ROUTERS
# =========================

app.include_router(auth_router)
app.include_router(admin_router)

# =========================
# HOME ROUTE
# =========================

@app.get("/")
def home():

    return {
        "message": "AutoSecCloud running successfully"
    }

# =========================
# PROTECTED ROUTE
# =========================

@app.get("/protected")
def protected_route(
    user=Depends(verify_token)
):

    return {
        "message": "Protected route accessed",
        "user": user
    }

# =========================
# ADMIN ONLY ROUTE
# =========================

@app.get("/admin-only")
def admin_route(
    user=Depends(verify_admin)
):

    return {
        "message": "Welcome Admin",
        "user": user
    }