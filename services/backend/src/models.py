from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import false, null
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.types import Date

from database import Base
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

class Record(Base):
    __tablename__ = "Records"

    id = Column(Integer, primary_key=True, index=True)
    date = Column(Date)
    country = Column(String(255), index=True)
    cases = Column(Integer)
    deaths = Column(Integer)
    recoveries = Column(Integer)

class User(Base):
    __tablename__ = "Users"

    id = Column(Integer, primary_key=True,autoincrement=True)
    email = Column(String(120), index=True, unique=True)
    password_hash = Column(String(128),nullable=True)
    boards = relationship('Board', back_populates='owner')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)    
        

class Board(Base):
    __tablename__ = "Boards"

    id = Column(Integer, primary_key=True,autoincrement=True)
    title = Column(String, nullable=false)
    owner_id = Column(Integer,ForeignKey("Users.id"))
    owner = relationship("User", back_populates="boards")

    cards = relationship('Card', back_populates='board',lazy="selectin",passive_deletes=True,cascade="all,delete")

""" Bridge_Cards_Tags = Table('Brg_Cards_Tags', Base.metadata,
    Column('card_id', ForeignKey('Cards.id'),primary_key=True),
    Column('board_id', ForeignKey('Boards.id'),primary_key=True)
)     """


class Card(Base):
    __tablename__ = "Cards"

    id = Column(Integer, primary_key=True,autoincrement=True)
    text = Column(String,default='new empty card')
    status = Column(String,default='new')
    created_time = Column(DateTime,default=datetime.now())    
    wip_time =  Column(DateTime,nullable=True)
    done_time = Column(DateTime,nullable=True)
    order_id = Column(Integer,nullable=True)

    board_id = Column(Integer,ForeignKey("Boards.id",ondelete='CASCADE'))
    board = relationship("Board", back_populates="cards") 

    #tags = relationship(
    #    "Tag",
    #    secondary=Bridge_Cards_Tags,
    #    back_populates="cards")

class Tag(Base):
    __tablename__ = "Tags"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer,ForeignKey("Users.id"))
    text = Column(String)

#    cards = relationship(
#        "Card",
#        secondary=Bridge_Cards_Tags,
#        back_populates="tags")    
