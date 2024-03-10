from fastapi import FastAPI, Query
from pydantic import BaseModel, Field
from pymongo import MongoClient
from os import environ
from typing import Annotated, Union
from bson import ObjectId
from time import time
from hashlib import sha512
from uvicorn import run
from enum import Enum
from string import ascii_letters
from random import choices

# sha512 encrypt function
s512 = lambda d: sha512(d.encode()).hexdigest()

# create application
app = FastAPI(
    title="ECSOKL",
    description="Elemental Services One Key Login API",
    version="0.1.0"
)

# connect database
db = MongoClient(
    environ.get("MONGODB_URI","mongodb://127.0.0.1:27017")
    )[
        environ.get("ECSOKL_MONGODB_DB","ECSOKL")
    ]

class Username(BaseModel):
    username : Annotated[str, Field(examples=["Administrator"])]

class Password(BaseModel):
    password: Annotated[str, Field(examples=["MyAdminPassword123"])]

class QR(BaseModel):
    qr: Annotated[str, Field(description="the QR code recorded when you registered. SuperAdmin doesn't have.", examples=["exampleQRCode"])]

class BasicAuthentication(Username, Password): pass

class UserPrivate(Username):
    permission: Annotated[int, Field(description="User's permission level", ge=0, le=999, examples=[1])] = 0
    allowQR : Annotated[bool, Field(description="Enable QR login", examples=[True])] = False

class User(UserPrivate, Password, QR): pass

class NewUserQueue(BaseModel):
    auth : Annotated[Union[BasicAuthentication,QR], Field(description="The user have enough permission to create a new user.")]
    new : Annotated[User, Field(description="The user profile you want to create.")]

class StatusCodeEnum(int, Enum):
    success = 1
    fail = -1

class ActionStatus(BaseModel):
    status : Annotated[StatusCodeEnum, Field(description="Status code of this action. `-1` for failed and `1` for success.",examples=[StatusCodeEnum.success])]


# initialize database
@app.get("/initialize", response_model=ActionStatus)
def initialize():
    """
    Initialize Application by Settings in Environ.
    """
    db.users.delete_many({"permission":999})
    db.users.drop_indexes()
    db.users.insert_one({
        "username": environ.get("ECSOKL_ADMIN_USERNAME","Administrator"),
        "password": s512(environ.get("ECSOKL_ADMIN_PASSWORD","MyAdminPassword123")),
        "permission": 999,
        "allowQR": False,
        "QR": ""
    })
    db.users.create_index("username",unique=True)
    db.users.create_index("QR",unique=True)
    return {
        "status": 1
    }

# delete all data
@app.get('/danger/factory_reset', response_model=ActionStatus)
def factory_reset(pwd:Annotated[str,Query(description="Factory reset key",examples=["exampleSecretKey"])]):
    """
    Remove all the data in database. [DANGER]
    """
    if pwd != environ.get("ECSOKL_FACTORY_RESET_KEY",''.join(choices(ascii_letters+'0123456789',k=16))):
        return {
            "status": -1
        }
    db.users.delete_many({})
    db.loginRequests.delete_many({})
    return {"status":1}

# new account
@app.post('/new',response_model=ActionStatus)
async def new_user(q:NewUserQueue):
    """
    Create a New Account by Permission(>=10)
    """
    if isinstance(q.auth, BasicAuthentication):
        authResult = db.users.find_one({
            "username": q.auth.username,
            'password': s512(q.auth.password)
        })
    elif isinstance(q.auth, QR):
        authResult = db.users.find_one({
            "allowQR": True,
            "QR": s512(q.auth.value),
            "permission": {"$ge":10}
        })
    else:
        authResult = None
    if authResult:
        db.users.delete_many({"$or":[
            {"username": q.new.username},
            {"QR": q.new.qr, "allowQR": True}
        ]})
        db.users.insert_one({
            "username": q.new.username,
            "password": s512(q.new.password),
            "permission": q.new.permission,
            "allowQR": q.new.allowQR,
            "QR": s512(q.new.qr)
        })
        return {
            "status": 1
        }
    return {
        "status": -1
    }

class LoginResp(ActionStatus):
    user : Union[UserPrivate,None] = None

# login by username and password
@app.post('/login',response_model=LoginResp)
async def login(q:Union[BasicAuthentication,QR]):
    """
    Login to the system.
    """
    result = db.users.find_one(
        {
            "username": q.username,
            "password": s512(q.password)
        }
        if isinstance(q, BasicAuthentication) else
        {
            "allowQR": True,
            "QR": s512(q.qr)
        }
    )
    return {
        "status": 1 if result else -1,
        "user": result
    }
class RequestID(BaseModel):
    request : Annotated[str, Field(description="The ID of the Request", examples=["65eb3b9af7fdbebd6de3b236"])]

class QRLoginQueue(QR, RequestID): pass

# login by qr code
@app.post("/qrlogin", response_model=ActionStatus)
async def login_by_QR(q:QRLoginQueue):
    """
    Login to the system by QR.
    """
    result = db.users.find_one({
        "allowQR": True,
        "QR": s512(q.qr)
    })
    if result:
        db.loginRequests.update_one(
            {
                "_id": ObjectId(q.request)
            },
            {
                "$set": {
                    "status": "completed",
                    "user": result,
                }
            }
        )
        return {
            "code": 1
        }
    return {
        "code": -1
    }

# new login request
@app.get('/newqr', response_model=RequestID)
async def new_login_request():
    """
    Add a new `pending` login request that can be `completed` by QR client.
    """
    return {
        "id": str(db.loginRequests.insert_one({
            "status": "pending",
            "time": time()
        }).inserted_id)
    }

# check login request
@app.get('/chkQr', response_model=LoginResp)
async def check_login_request(r:Annotated[str,Query(description="The ID of the Request.",examples=["65eb3b9af7fdbebd6de3b236"])]):
    """
    Check that does the Request have completed.
    """
    result = db.loginRequests.find_one({
        "_id": ObjectId(r),
        "status": "completed"
    })
    return {
        "status": 1 if result else -1,
        "user": result.get("user")
    }

# automatically remove timeout pending login request
@app.get("/clean",response_model=ActionStatus)
def remove_timed_out_login_requests():
    """
    Clean the database by deleting timed out login requests.
    """
    db.loginRequest.delete_many({"time":{"$lt":time()-3600}})
    return {"status":1}

if __name__=="__main__":
    run(
        app,
        host=environ.get("ECSOKL_HOST","127.0.0.1"),
        port=environ.get("ECSOKL_PORT",8099)
    )