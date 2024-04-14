import time
from typing import Annotated
from fastapi import HTTPException
from jose import jwt, JWTError
from passlib.context import CryptContext
from decouple import config
import bcrypt
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
contain_header = HTTPBearer()



pwd_context = CryptContext(schemes=['bcrypt'],deprecated='auto')

ACCESS_SECRET = config('secret_access')
REFRESH_SECRET = config('secret_refresh')
ALGORITHM = config('algorithm')

def generate_JWT(email:str,):
    payload = {
        'user_identifier':email, 
        'expiry': time.time() + 1200
        }
    encoded_access = jwt.encode(payload,ACCESS_SECRET,algorithm=ALGORITHM)
    payload = {
        'user_identifier':email, 
        'expiry': time.time() + 604800
        }
    encoded_refresh = jwt.encode(payload,REFRESH_SECRET,ALGORITHM)
    return encoded_access, encoded_refresh

def decodAccessJWT(token:str):
    try:
        decode_token = jwt.decode(token,ACCESS_SECRET,ALGORITHM)
        # return decode_token if decode_token['expiry'] >= time.time() else None
        if decode_token['expiry'] >= time.time():
            return decode_token
        else:
            raise HTTPException(
                status_code=401,
                detail="Expired Token"
            )   
            
    except JWTError:
        raise HTTPException(
                    status_code=401,
                    detail="Token Verification failed"
                )    


def decodRefreshJWT(token:str):
    try:
        decode_token = jwt.decode(token,REFRESH_SECRET,ALGORITHM)
        # return decode_token if decode_token['expiry'] >= time.time() else None
        if decode_token['expiry'] >= time.time():
            new_token, _ = generate_JWT(decode_token['user_identifier'])
            return new_token
        else:
            raise HTTPException(
                status_code=401,
                detail="Expired Token"
            )   
    except JWTError:
        raise HTTPException(
                    status_code=401,
                    # detail=
                    detail='Token verivication Failed'
                ) 


def hash_password(password):
    pwd_bytes = password.encode('UTF-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password.decode()


def verify_password(plain_password:str, hashed_password):
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc , hashed_password)

def validate_token(token: Annotated[HTTPAuthorizationCredentials,Depends(contain_header)]):
    return decodAccessJWT(token.credentials)
