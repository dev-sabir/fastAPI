from fastapi import FastAPI
from dotenv import load_dotenv, find_dotenv
import jwt
import bcrypt
import os

load_dotenv(find_dotenv())
os.getenv('ASSCESS_SECRET')
ACCESS_SECRET = os.getenv('ACCESS_SECRET')

app = FastAPI()

UsersData = {}


@app.get('/')
def home():
    return "Please go to http://127.0.0.1:8000/docs for further details"


@app.post("/api/signup")
def add_data(full_name, user_name, password, browser="Unknown"):
    if user_name in UsersData.keys():
        return "User_name already exist please try another user_name."

    temp_user = {"name": user_name}
    access_token = jwt.encode(temp_user, ACCESS_SECRET)

    # THE REASON: WE HAVE TO ENCODE THE PASSWORD IS BECAUSE
    # CRYPTOGRAPHIC FUNCTIONS ONLY WORK ON BYTES STRINGS
    password = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt)

    UsersData[user_name] = {"full_name": full_name, "password": hashed_password,
                            "LoggedInBrowser": [{"browser": browser, "access_token": access_token}]}

    return f"Account Created Successfully!! {UsersData[user_name]} "


@app.post("/api/login")
def login(user_name, password, browser="Unknown"):
    if user_name not in UsersData.keys():
        return "Ivalid user_name or password"
    password = password.encode("utf-8")

    if bcrypt.checkpw(password, UsersData[user_name]["password"]):
        temp_user = {"name": user_name}
        access_token = jwt.encode(temp_user, ACCESS_SECRET)
        UsersData[user_name]["LoggedInBrowser"].append(
            {"browser": browser, "access_token": access_token})
        return f"Logged in Successfully your access token is: {access_token} "

    return "Invalid user_name or password"


@app.put("/api/change-password")
def change_password(access_token, new_password, browser="unknown"):
    try:
        # Reason to put in try is because if access_token is wrong it raise an error
        temp_user = jwt.decode(
            access_token, ACCESS_SECRET, algorithms=["HS256"])
        user_name = temp_user["name"]
        full_name = UsersData[user_name]["full_name"]
        if user_name not in UsersData.keys():
            return "Invalid access_token"
        new_password = new_password.encode("utf-8")
        salt = bcrypt.gensalt()
        new_hashed_password = bcrypt.hashpw(new_password, salt)
        UsersData[user_name] = {"full_name": full_name, "password": new_hashed_password,
                                "LoggedInBrowser": [{"browser": browser, "access_token": access_token}]}
        return f"Password Changed Successfully!! Your access_token is: {access_token} "
    except:
        return "Invalid access_token"


@app.get("/api/users_data")
def get_all_users_data():
    return UsersData


@app.get("/api/user")
def get_user(access_token):
    try:
        temp_user = jwt.decode(
            access_token, ACCESS_SECRET, algorithms=["HS256"])
        user_name = temp_user["name"]
        if user_name not in UsersData.keys():
            return "Invalid access_token"
        return UsersData[user_name]
    except:
        return "Invalid access_token"
