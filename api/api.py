from fastapi import FastAPI
from pydantic import BaseModel
from os.path import exists, abspath, split
from pymongo import MongoClient
from os import environ
from typing import Union
from bson import ObjectId
from time import time, sleep
from threading import Thread
from hashlib import sha512
from uvicorn import run

# sha512 encrypt function
s512 = lambda d: sha512(d).hexdigest()

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
    db.users.insert_one({
        "username": environ.get("ECSOKL_ADMIN_USERNAME","Administrator"),
        "password": s512(environ.get("ECSOKL_ADMIN_PASSWORD","MyAdminPassword123")),
        "permission": 999,
        "allowQR": False,
        "QR": ""
    })
    db.users.create_index("username",unique=True)
    db.users.create_index("QR",unique=True)

# new account
@app.post('/new')
async def newUser(auth:dict[str,str], new:dict[str,Union[str,bool]]):
    if auth.get('username') and auth.get('password'):
        authResult = db.users.find_one({
            "username": auth['username'],
            'password': auth['password']
        })
    elif auth.get('qr'):
        authResult = db.users.find_one({
            "allowQR": True,
            "QR": s512(auth['qr'])
        })
    else:
        authResult = None
    if authResult:
        db.users.insert_one(new)

# login by username and password
@app.post('/login')
async def login(username:str, password:str):
    return db.users.find_one({
        "username": username,
        "password": s512(password)
    })

# login by qr code
@app.post("/qrlogin")
async def loginByQR(qr:str, pendingRequest:str):
    if db.users.find_one({
        "allowQR": True,
        "QR": qr
    }):
        db.loginRequests.update_one(
            {
                "_id": ObjectId(pendingRequest)
            },
            {
                "$set": {
                    "status": "completed"
                }
            }
        )
        return {
            "type": "success"
        }
    return {
        "type": "error",
        "msg": "Wrong QR Scanner."
    }

# new login request
@app.get('/newqr')
async def newPendingLoginRequest():
    return db.loginRequests.insert_one({
        "status": "pending",
        "time": time()
    }).inserted_id

# check login request
@app.get('/chkQr')
async def checkPendingLoginRequest(r:str):
    tryRMTPLRP()
    if db.loginRequests.find_one({
        "_id": ObjectId(r),
        "status": "completed"
    }):
        return 

# automatically remove timeout pending login request
def rmTimeoutPendingLoginRequests():
    db.loginRequest.delete_many({"time":{"$lt":time()-600}})
    sleep(600)
rmtplrP = Thread(target=rmTimeoutPendingLoginRequests)
rmtplrP.start()

def tryRMTPLRP():
    if rmtplrP.is_alive():
        return
    rmtplrP = Thread(target=rmTimeoutPendingLoginRequests)
    rmtplrP.start()