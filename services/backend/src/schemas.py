from datetime import date, datetime
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

class Record(BaseModel):
    id: int
    date: date
    country: str
    cases: int
    deaths: int
    recoveries: int

    class Config:
        orm_mode = True

class Settings(BaseModel):
    authjwt_secret_key: str = "my_jwt_secret"  


class User(BaseModel):
    email: str
    password: str = None

    class Config:
        orm_mode = True    

class Board(BaseModel):
    title: str 
    id: int
    owner_id: int # email-address

class Card(BaseModel):
    id : int # PK
    board_id : int # FK
    text : str 
    status : str
    created_time : datetime
    wip_time: Optional[datetime]
    done_time: Optional[datetime]
    order_id: int 

    class Config:
        orm_mode = True

class Tag(BaseModel):
    owner: str
    text: str

class CardOrders(BaseModel):
    board_id: int
    items: List[List]  # id,order_id