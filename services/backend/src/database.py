import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = 'sqlite:///db.sqlite'
# same thread error
# https://stackoverflow.com/questions/48218065/programmingerror-sqlite-objects-created-in-a-thread-can-only-be-used-in-that-sa
engine = create_engine(SQLALCHEMY_DATABASE_URL,
                        echo=True,
                        connect_args={"check_same_thread": False},
                        #use_lifo=False, # for Postgres
                        #pool_size=5,
                        #max_overflow=2
                        )
#keepalive in URI for postgres: https://docs.google.com/presentation/d/1PDFYvNheocsaVLVu4ibqplJTzOuKnkaS_AX3_Mhczmw/edit#slide=id.g52b1b0b3f2_0_445                        
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine,)

Base = declarative_base()