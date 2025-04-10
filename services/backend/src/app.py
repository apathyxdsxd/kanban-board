from typing import Any, Optional, Text
import datetime
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import text
from sqlalchemy.sql import case
from werkzeug.security import check_password_hash
from contextlib import contextmanager
import models
from schemas import *
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

@contextmanager
def session_manager():
    db = SessionLocal()    
    try:
        yield db
    except:
        db.rollback()
        raise
    finally:
        db.close()

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

@app.get("/")
def read_root():
    return {"Hello": "World Rasyue"}

@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):        
    with session_manager() as db:
        exists = db.query(models.User).filter_by(email=user.email).first()
        if exists == None:
            return JSONResponse(status_code=500, content={"message": 'User not found'})        
        if(check_password_hash(exists.password_hash, user.password)):
            access_token = Authorize.create_access_token(subject=user.email,expires_time=86400000)
            return {"access_token": access_token}
        else:
            return JSONResponse(status_code=500, content={"message": 'Wrong password'})        

@app.post('/register',status_code=201)
def register(user:User):    
    with session_manager() as db:
        exists = bool(db.query(models.User).filter_by(email=user.email).first())
        if exists:
            return JSONResponse(status_code=500, content={"message": 'Email already registered'})              
        u = models.User(email=user.email)
        u.set_password(user.password)
        db.add(u)
        db.commit()
        return {"email": user.email, 'msg':'new user created'}

@app.get('/test-jwt')
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()    
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        result = user.id    
        return {"user": current_user_mail, 'user_id': result}    

@app.get('/getBoards')
def getBoards(Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        result = db.query(models.Board).join(models.Card,isouter=True).join(models.User).filter(models.User.id ==user.id).order_by(models.Card.order_id).all()
        return result
    
@app.get('/getCards',status_code=201,response_model=List[Card])
def getCards(boardId:int,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id        
        board = db.query(models.Board).filter(models.Board.id == boardId).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            result=db.query(models.Card).filter(models.Card.board_id == board.id).order_by(models.Card.order_id).all()
            return [card.__dict__ for card in result]
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})            
            
@app.post('/createEmptyBoard',status_code=201)
def createEmptyBoard(Title:str,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id                    
        board=models.Board(title=Title,owner_id=user_id)
        db.add(board)
        db.commit()
        return {"id":board.id, "owner_id":user_id,"title":board.title}        

@app.post('/renameBoard',status_code=201)
def createEmptyBoard(board:Board,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id                    
        result = db.query(models.Board).filter(models.Board.id == board.id).filter(models.Board.owner_id == user_id).one_or_none()
        if(result):
            result.title=board.title
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})                
        db.commit()
        return result

@app.post('/deleteBoard',status_code=201)
def deleteBoard(board:Board,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id                    
        result = db.query(models.Board).filter(models.Board.id == board.id).filter(models.Board.owner_id == user_id).one_or_none()
        if(result):
            db.delete(result)            
            db.commit()
            return JSONResponse(status_code=200, content={"message": 'Board deleted'})            
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})
            
@app.post('/deleteCard',status_code=201)
def deleteCard(boardId:int,cardId:int,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id         
        board = db.query(models.Board).filter(models.Board.id == boardId).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            result = db.query(models.Card).filter(models.Card.board_id==boardId).filter(models.Card.id==cardId).one_or_none()
            if(result):
                db.delete(result)            
                db.commit()
                return JSONResponse(status_code=200, content={"message": 'Card deleted'})            
            else:
                return JSONResponse(status_code=500, content={"message": 'Card not found'})                                    
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})   
            
@app.post('/createEmptyCard',status_code=201,response_model=Card)
def createEmptyCard(boardId:int,column:Text,Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id         
        board = db.query(models.Board).filter(models.Board.id == boardId).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            count=0
            result = db.query(models.Card).filter(models.Card.board_id==boardId).all()
            if result:
                count=len(result)
            card=models.Card(board_id=boardId,order_id=count+1)
            if column == 'activeColumn':
                card.status = 'wip'
                card.wip_time = datetime.now()
            elif column == 'doneColumn':
                card.status = 'done'
                card.done_time = datetime.now()
            db.add(card)
            db.commit()
            pydantic_card = Card.from_orm(card)
            return pydantic_card                            
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})        

@app.post('/renameCard',status_code=201)
def renameCard(boardId:int,cardId:int, newText:Text, Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id         
        board = db.query(models.Board).filter(models.Board.id == boardId).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            result = db.query(models.Card).filter(models.Card.id == cardId).one_or_none()
            if(result):
                result.text=newText
                db.commit()
            else:
                return JSONResponse(status_code=500, content={"message": 'Board not found'})                                            
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})        
            
@app.post('/reorderItems',status_code=201)
def reorderItems(cardOrders:CardOrders, Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id         
        board = db.query(models.Board).filter(models.Board.id == cardOrders.board_id).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            payload=dict(cardOrders.items)
            db.query(models.Card).filter(models.Card.id.in_(payload)).update({
                models.Card.order_id: case(payload, value=models.Card.id, else_=models.Card.order_id)
            }, synchronize_session=False)            
            db.commit()
            return JSONResponse(status_code=200, content={"message": "OK"})
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})               

@app.post('/moveItem',status_code=201)
def moveItem(board_id:int,card_id:int,card_status:str, Authorize:AuthJWT=Depends()):
    Authorize.jwt_required()
    current_user_mail = Authorize.get_jwt_subject()
    with session_manager() as db:
        user:models.User = db.query(models.User).filter_by(email=current_user_mail).first()
        user_id = user.id         
        board = db.query(models.Board).filter(models.Board.id == board_id).filter(models.Board.owner_id == user_id).one_or_none()
        if board:
            change_date_mapper={'new':'created_time','wip':'wip_time','done':'done_time'}
            db.query(models.Card).filter((models.Card.id == card_id) & (models.Card.board_id == board_id)).update({
                "status":card_status, change_date_mapper[card_status]:datetime.now()
            })
            db.commit()
            return JSONResponse(status_code=200, content={"message": "OK"})
        else:
            return JSONResponse(status_code=500, content={"message": 'Board not found'})                

