from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean 
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base
from decouple import config

Base = declarative_base()

class User(Base):
  __tablename__ = "Users"
  uni = Column(String(50), primary_key=True)
  swipes_given = Column(Integer, default=0)
  swipes_received = Column(Integer, default=0)
  points_given = Column(Integer, default=0)
  points_received = Column(Integer, default=0)
  current_points = Column(Integer, default=-1)
  current_swipes = Column(Integer, default=-1)

class Swipe(Base):
  __tablename__ = "Swipes"  
  swipe_id = Column(Integer, primary_key=True, autoincrement=True)  
  uni = Column(String(50), ForeignKey("Users.uni", ondelete="CASCADE"), nullable=False) 
  is_donated = Column(Boolean, default=False)
  
class Transaction(Base):
    __tablename__ = "Transactions"
    transaction_id = Column(Integer, primary_key=True, autoincrement=True)
    swipe_id = Column(Integer, ForeignKey("Swipes.swipe_id"), nullable=False)
    donor_id = Column(String(50), ForeignKey("Users.uni"), nullable=False)
    recipient_id = Column(String(50), ForeignKey("Users.uni"), nullable=False)
    transaction_date = Column(DateTime, default=datetime.utcnow)
  
class Points(Base):
    __tablename__ = "Points"
    id = Column(Integer, primary_key=True, autoincrement=True)
    points = Column(Integer, default=0, nullable=False)  

# Database setup
DATABASE_URL = config("DATABASE_URL")
engine = create_engine(DATABASE_URL, echo=True)  # Set echo=True to debug queries
# DATABASE_URL = "mysql+mysqlconnector://admin:care2share@care2share-db.clygygsmuyod.us-east-1.rds.amazonaws.com/care2share_database"

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def cleanup_database():
    try:
        logger.info("Dropping tables in the correct order...")
        # Drop dependent tables first
        Points.__table__.drop(bind=engine, checkfirst=True)
        Transaction.__table__.drop(bind=engine, checkfirst=True)
        Swipe.__table__.drop(bind=engine, checkfirst=True)
        User.__table__.drop(bind=engine, checkfirst=True)
        logger.info("Tables dropped successfully.")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def initialize_database():
    try:
        cleanup_database()
        logger.info("Initializing database...")
        logger.info("Creating Users table first...")
        User.__table__.create(bind=engine, checkfirst=True)  # Create Users table first
        logger.info("Creating Swipes table next...")
        Swipe.__table__.create(bind=engine, checkfirst=True)  # Create Swipes table after Users
        logger.info("Creating Transactions table next...")
        Transaction.__table__.create(bind=engine, checkfirst=True)  # Create Transactions table after Users
        logger.info("Creating Points table last...")
        Points.__table__.create(bind=engine, checkfirst=True)  # Create Transactions table after Users
        logger.info("Database initialized successfully!")
        print("Table details:")
        for table_name, table in Base.metadata.tables.items():
            print(f"Table: {table_name}")
            for column in table.columns:
                print(f"  Column: {column.name}, Type: {column.type}, Nullable: {column.nullable}")
            print(f"  Primary Key: {[key.name for key in table.primary_key]}")
            for fk in table.foreign_keys:
                print(f"  Foreign Key: {fk.parent.name} references {fk.column}")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
