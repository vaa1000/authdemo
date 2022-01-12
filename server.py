import base64
import hmac
import hashlib
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "5f0bb4ac71f76f59d2da01acda08c7569c171225ad2abe12b3b96bb4c9d6572a"
PASSWORD_SALT = "f7a2e928e00a59cf86c5bb5bbe773dcf50b78f223689d70d58f10479dc584550"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные дата"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() )\
        .hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "3f9cda2026433c087b49e17d903434d57a0247ec0b3ad2c476039befae491ef3",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "45182d7003c3f35c5aab4a7cf76f98929ca75eb210c818dfce3d9061664851b0",
        "balance": 555_555
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default = None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет {users[valid_username]['name']}!<br />"\
        f"Баланс {users[valid_username]['balance']}",
        media_type="text/html")

@app.post("/login")
def process_login_page(data: dict = Body(...)):
    print("data is", data)
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "succes": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "succes": True,
            "message": f"Привет {user['name']}!<br/> Баланс {user['balance']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)

    response.set_cookie(key="username", value=username_signed)
    return response