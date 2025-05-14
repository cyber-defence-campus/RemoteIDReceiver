import logging

from sqlmodel import create_engine, SQLModel, Session

from models.direct_remote_id import SystemMessage, Base, BasicIdMessage, LocationMessage, SelfIdMessage, OperatorMessage, DjiMessage
from typing import List
import logging

# required for FastAPI - we ensure that sessions are
# not shared with more than one request
connect_args = {"check_same_thread": False}
# single engine object for WHOLE project
engine = create_engine("sqlite:///remoteid.db", connect_args=connect_args)

LOG = logging.getLogger(__name__)

def setup_database() -> None:
    """
    Method to set up database and create tables from metadata.

    Important: make sure that all the SQLModels that represent tables (table=True) have been initialized before
    executing this method. Otherwise, the tables will not be created in the database.
    """
    LOG.info("setting up database and tables")
    SQLModel.metadata.create_all(engine)
    Base.metadata.create_all(engine)


def save_messages(messages: List[SystemMessage | BasicIdMessage | LocationMessage | SelfIdMessage | OperatorMessage | DjiMessage]) -> None:
    """
    Saves a list of drone flight info packet objects to the db.

    Args:
        message (List[SystemMessage | BasicIdMessage | LocationMessage | SelfIdMessage | OperatorMessage]): Drone info
    """
    LOG.info(f"Saving {len(messages)} messages to the database")
    
    with Session(engine) as session:
        session.add_all(messages)
        session.commit()