# backend/app/api/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import Optional
import httpx
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt

from app.db.session import get_db
from app.db.models import User
from app.config import get_settings




settings  = get_settings()
router    = APIRouter()
ALGORITHM = "HS256"


@router.get("/auth/github")
async def github_login():
    # step 1 — redirect user to GitHub OAuth page
    # GitHub shows "SecureRepo wants to access your account" UI
    github_auth_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={settings.github_client_id}"
        f"&redirect_uri={settings.github_redirect_uri}"
        f"&scope=repo,read:user,user:email"
        # scope=repo      → read private repos (what we need for scanning)
        # scope=read:user → get username and avatar
        # scope=user:email→ get email address
    )
    return RedirectResponse(url=github_auth_url)


@router.get("/auth/github/callback")
async def github_callback(
    code: str,
    db: AsyncSession = Depends(get_db),
):
    # step 2 — GitHub redirects back here with a ?code=xxx
    # we exchange that code for an access token

    async with httpx.AsyncClient() as client:
        # exchange code for access token
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id"    : settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code"         : code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()

    github_token = token_data.get("access_token")
    if not github_token:
        raise HTTPException(400, "GitHub OAuth failed — no access token returned")

    # step 3 — use the token to get user info from GitHub
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept"       : "application/vnd.github+json",
            },
        )
        github_user = user_response.json()

    # step 4 — upsert user in our DB
    # if they've logged in before, update their token
    # if new user, create them
    result = await db.execute(
        select(User).where(User.github_id == str(github_user["id"]))
    )
    user = result.scalar_one_or_none()

    if user:
        # existing user — update token (it can change on re-auth)
        user.access_token = github_token
        user.avatar_url   = github_user.get("avatar_url")
    else:
        # new user
        user = User(
            github_id    = str(github_user["id"]),
            username     = github_user["login"],
            email        = github_user.get("email"),
            avatar_url   = github_user.get("avatar_url"),
            access_token = github_token,
        )
        db.add(user)

    await db.commit()
    await db.refresh(user)

    # step 5 — create our own JWT for the user
    # from this point on, frontend uses OUR JWT, not GitHub's token
    # GitHub token stays on the server — never sent to frontend
    our_jwt = jwt.encode(
        {
            "sub" : str(user.id),
            "exp" : datetime.utcnow() + timedelta(days=7),
            # 7 day expiry — user stays logged in for a week
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    # redirect to frontend with the JWT
    # frontend stores this in memory (not localStorage — XSS risk)
    return RedirectResponse(
        url=f"{settings.frontend_url}/auth/callback?token={our_jwt}"
    )


@router.get("/auth/me")
async def get_me(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "no token")

    token = authorization.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(401, "invalid token")

    result = await db.execute(select(User).where(User.id == user_id))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "user not found")

    return {
        "id"        : str(user.id),
        "username"  : user.username,
        "email"     : user.email,
        "avatar_url": user.avatar_url,
    }