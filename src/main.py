"""
Main module
"""
from http.client import HTTPException
from fastapi import FastAPI
from .auth import AuthHandler
from .schemas import AuthDetails


app = FastAPI()


auth_handler = AuthHandler()
users = []


@app.post('/register')
def register(auth_details: AuthDetails):
    '''
    Rest fastApi register service
    '''
    if any(x['username'] == auth_details.username for x in users):
        raise HTTPException(status_code=400, detail='Username is taken')
    return {}


@app.post('/login')
def login():
    '''
    Rest fastApi login service
    '''
    return {}


@app.get('/unprotected')
def unprotected():
    '''
    Rest fastApi unprotected service
    '''
    return {'hello': 'world'}


@app.get('/protected')
def protected():
    '''
    Rest fastApi jwt protected service
    '''
    return {}
