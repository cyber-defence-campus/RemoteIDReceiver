from fastapi import APIRouter
from sqlalchemy.orm import Session
from info_handler import engine
from models.direct_remote_id import BasicIdMessage, LocationMessage, SelfIdMessage, SystemMessage, OperatorMessage
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

# Define Pydantic models for each message type
class BasicIdMessageDto(BaseModel):
    sender_id: str
    uas_id: str | None

    class Config:
        from_attributes = True

class LocationMessageDto(BaseModel):
    sender_id: str
    latitude: float | None
    longitude: float | None

    class Config:
        from_attributes = True

class SelfIdMessageDto(BaseModel):
    sender_id: str
    description: str | None
    received_at: datetime
    description_type: int | None

    class Config:
        from_attributes = True

class SystemMessageDto(BaseModel):
    sender_id: str
    ua_category: int | None
    ua_class: int | None
    received_at: datetime
    classification_type: int | None
    location_source: int | None
    pilot_latitude: float | None
    pilot_longitude: float | None
    area_count: int | None
    area_radius: int | None
    area_ceiling: int | None
    area_floor: int | None
    pilot_geodetic_altitude: int | None

    class Config:
        from_attributes = True

class OperatorMessageDto(BaseModel):
    sender_id: str
    operator_id: str | None
    received_at: datetime
    operator_id_type: int | None

    class Config:
        from_attributes = True

@router.get("/api/ads_stan/basic_id", response_model=list[BasicIdMessageDto], description="Retrieve all Basic ID messages, optionally filtered by sender_id.")
def get_basic_id_messages(sender_id: str = None) -> list[BasicIdMessageDto]:
    with Session(engine) as session:
        query = session.query(BasicIdMessage)
        if sender_id:
            query = query.filter(BasicIdMessage.sender_id == sender_id)
        return query.all()

@router.get("/api/ads_stan/location", response_model=list[LocationMessageDto], description="Retrieve all Location messages, optionally filtered by sender_id.")
def get_location_messages(sender_id: str = None) -> list[LocationMessageDto]:
    with Session(engine) as session:
        query = session.query(LocationMessage)
        if sender_id:
            query = query.filter(LocationMessage.sender_id == sender_id)
        return query.all()

@router.get("/api/ads_stan/self_id", response_model=list[SelfIdMessageDto], description="Retrieve all Self ID messages, optionally filtered by sender_id.")
def get_self_id_messages(sender_id: str = None) -> list[SelfIdMessageDto]:
    with Session(engine) as session:
        query = session.query(SelfIdMessage)
        if sender_id:
            query = query.filter(SelfIdMessage.sender_id == sender_id)
        return query.all()

@router.get("/api/ads_stan/system", response_model=list[SystemMessageDto], description="Retrieve all System messages, optionally filtered by sender_id.")
def get_system_messages(sender_id: str = None) -> list[SystemMessageDto]:
    with Session(engine) as session:
        query = session.query(SystemMessage)
        if sender_id:
            query = query.filter(SystemMessage.sender_id == sender_id)
        return query.all()

@router.get("/api/ads_stan/operator", response_model=list[OperatorMessageDto], description="Retrieve all Operator ID messages, optionally filtered by sender_id.")
def get_operator_messages(sender_id: str = None) -> list[OperatorMessageDto]:
    with Session(engine) as session:
        query = session.query(OperatorMessage)
        if sender_id:
            query = query.filter(OperatorMessage.sender_id == sender_id)
        return query.all()
