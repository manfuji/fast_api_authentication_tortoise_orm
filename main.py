from fastapi import FastAPI, Depends, HTTPException, status
from tortoise import BaseDBAsyncClient
from tortoise.contrib.fastapi import register_tortoise
from models import *
from utils.encryption import *
from passlib.hash import bcrypt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt

# signals
from tortoise.signals import post_save
from typing import List, Optional, Type

# instatitations
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# secrets
Token_secret = "wewanttoeatapp"


@app.get("/healthcheck")
async def read_root():
    return {"status": "ok"}


register_tortoise(
    app,
    db_url="sqlite://database.sqlite3",
    modules={'models': ['models']},
    generate_schemas=True,
    add_exception_handlers=True,
)


async def authenticate(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False

    return user


@app.post('/token')
async def generate_token(formdata: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate(formdata.username, formdata.password)
    print(user)
    if not user:
        return {"message": "Incorrect username or password"}

    user_obj = await user_pydanticOut.from_tortoise_orm(user)
    token = jwt.encode({'user_id': user_obj.username},
                       Token_secret, algorithm="HS256")

    print(token)
    return {"access_token": token, 'token_type': 'bearer'}


async def Permissions(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, Token_secret, algorithms="HS256")
        user_obj = await User.get(username=payload.get('user_id'))

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized Access")

    return user_obj


@app.post('/login')
async def Login(user: user_pydanticLogin = Depends(Permissions)):
    userOut = await user_pydanticOut.from_tortoise_orm(user)
    return {
        'user': userOut
    }


@post_save(User)
async def create_Profile(
        sender: 'Type[User]',
        instance: User,
        created: bool,
        using_db: 'Optional[BaseDBAsyncClient]',
        update_fileds: List[str]) -> None:

    if created:
        profile_obj = await Profile.create(user_id=instance, bio="happy child")
        await profile_pydantic.from_tortoise_orm(profile_obj)


@app.post("/registration")
async def create_user(user: user_pydanticIn):
    user_data = user.dict(exclude_unset=True)
    user_data['password'] = bcrypt.hash(user_data['password'])
    create_user = await User.create(**user_data)
    created_user = await user_pydanticOut.from_tortoise_orm(create_user)
    return {
        'status': 'ok',
        'msg': f"hello {created_user.username} please check your email to confirm your registration to continue"
    }


@app.post("/profile")
async def UserProfile(user: user_pydanticLogin = Depends(Permissions)):
    profile = await Profile.get(user_id=user)
    profileOut = await profile_pydanticOut.from_tortoise_orm(profile)
    return {"details": profileOut}
