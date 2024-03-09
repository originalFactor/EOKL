from fastapi import FastAPI, Query, Form
from pydantic import BaseModel, Field
from os.path import exists, abspath, split
from pymongo import MongoClient
from os import environ
from typing import Annotated
from bson import ObjectId
from time import time, sleep
from multiprocessing import Process, freeze_support
from hashlib import sha512
from pymongo.errors import DuplicateKeyError
from uvicorn import run
from enum import Enum

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

# get program directory
directory = split(abspath(__file__))[0]

# initialize database
if not exists(directory+'/.initialized'):
    try:
        db.users.insert_one({
            "username": environ.get("ECSOKL_ADMIN_USERNAME","Administrator"),
            "password": s512(environ.get("ECSOKL_ADMIN_PASSWORD","MyAdminPassword123")),
            "permission": 999,
            "allowQR": False,
            "QR": ""
        })
        db.users.create_index("username",unique=True)
        db.users.create_index("QR",unique=True)
    except DuplicateKeyError:
        print("Already initialized. Someone deleted .initialized file, recovering...")
        db.users.update_one({"permission":999}, {"$set":{
            "username": environ.get("ECSOKL_ADMIN_USERNAME","Administrator"),
            "password": s512(environ.get("ECSOKL_ADMIN_PASSWORD","MyAdminPassword123")),
        }})
    open(directory+'/.initialized','w').close()

class LoginByPWD(BaseModel):
    username : Annotated[str, Field(examples=["Administrator"])]
    password: Annotated[str, Field(examples=["MyAdminPassword123"])]

class LoginByQR(BaseModel):
    value: Annotated[str, Field(description="the QR code recorded when you registered. SuperAdmin doesn't have.", examples=["exampleQRCode"])]

class UserPrivate(BaseModel):
    username : Annotated[str, Field(examples=["exampleUser"])]
    permission: Annotated[int, Field(description="User's permission level", ge=0, le=999, examples=[1])] = 0
    allowQR : Annotated[bool, Field(description="Enable QR login", examples=[True])] = False

class User(UserPrivate):
    password : Annotated[str, Field(examples=["examplePassword"])]
    QR : Annotated[str|None, Field(description="QR code. You must provide this if `allowQR` is `true` for safety reasons.", examples=["exampleQRCodeValue"])] = None

class NewUserQueue(BaseModel):
    auth : Annotated[LoginByPWD|LoginByQR, Field(description="The user have enough permission to create a new user.")]
    new : Annotated[User, Field(description="The user profile you want to create.")]

class StatusCodeEnum(int, Enum):
    success = 1
    fail = -1

class ActionStatus(BaseModel):
    status : Annotated[StatusCodeEnum, Field(description="Status code of this action. `-1` for failed and `1` for success.",examples=[StatusCodeEnum.success])]

# new account
@app.post('/new',response_model=ActionStatus)
async def new_user(q:NewUserQueue):
    """
    Create a New Account by Permission(>=10)
    """
    if isinstance(q.auth, LoginByPWD):
        authResult = db.users.find_one({
            "username": q.auth.username,
            'password': s512(q.auth.password)
        })
    elif isinstance(q.auth, LoginByQR):
        authResult = db.users.find_one({
            "allowQR": True,
            "QR": s512(q.auth.value),
            "permission": {"$ge":10}
        })
    else:
        authResult = None
    if authResult:
        try:
            db.users.insert_one({
                "username": q.new.username,
                "password": s512(q.new.password),
                "permission": q.new.permission,
                "allowQR": q.new.allowQR,
                "QR": s512(q.new.QR)
            })
            return {
                "code": 1
            }
        except DuplicateKeyError: pass
    return {
        "code": -1
    }

class LoginResp(ActionStatus):
    user : UserPrivate|None = None

class PasswordLoginQueue(BaseModel):
    username : Annotated[str, Field(examples=["exampleUsername"])]
    password : Annotated[str, Field(examples=["examplePassword"])]

# login by username and password
@app.post('/login',response_model=LoginResp)
async def login(q:PasswordLoginQueue):
    """
    Login to the system by username&password.
    """
    result = db.users.find_one({
        "username": q.username,
        "password": s512(q.password)
    })
    return {
        "status": 1 if result else -1,
        "user": result
    }

class QRLoginQueue(BaseModel):
    QR : Annotated[str, Field(
        description="the value of QR Code of the account you want to login.",
        examples=["exampleQRCode"]
    )]
    request : Annotated[str, Field(
        description="The ID of the login request, regularly you can get it from the QR Code the login page are showing.",
        examples=["65eb3b9af7fdbebd6de3b236"]
    )]

# login by qr code
@app.post("/qrlogin", response_model=ActionStatus)
async def login_by_QR(q:QRLoginQueue):
    """
    Login to the system by QR.
    """
    result = db.users.find_one({
        "allowQR": True,
        "QR": s512(q.QR)
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

class RequestID(BaseModel):
    id : Annotated[str, Field(description="The ID of the Request", examples=["65eb3b9af7fdbebd6de3b236"])]

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
def remove_timed_out_login_requests():
    while True:
        db.loginRequest.delete_many({"time":{"$lt":time()-3600}})
        sleep(3600)

rmtplr_t = Process(target=remove_timed_out_login_requests,daemon=True)
rmtplr_t.start()

if __name__=="__main__":
    run(
        app,
        host=environ.get("ECSOKL_HOST","127.0.0.1"),
        port=environ.get("ECSOKL_PORT",8099)
    )