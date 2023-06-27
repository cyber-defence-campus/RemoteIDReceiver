import logging

from sqlmodel import create_engine, SQLModel, Session

from models import RemoteId
from ws_manager import broadcast

# required for FastAPI - we ensure that sessions are
# not shared with more than one request
connect_args = {"check_same_thread": False}
# single engine object for WHOLE project
engine = create_engine("sqlite:///remoteid.db", connect_args=connect_args)


def setup_database() -> None:
    """
    Method to set up database and create tables from metadata.

    Important: make sure that all the SQLModels that represent tables (table=True) have been initialized before
    executing this method. Otherwise, the tables will not be created in the database.
    """
    logging.info("setting up database and tables")
    SQLModel.metadata.create_all(engine)


def save_drone_info(info: RemoteId) -> None:
    """
    Saves a drone flight info packet object to the db.

    Args:
        info (RemoteId): Drone info
    """
    broadcast(info)
    with Session(engine) as session:
        session.add(info)
        session.commit()
