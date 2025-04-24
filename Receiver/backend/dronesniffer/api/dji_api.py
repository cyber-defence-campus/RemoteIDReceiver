from fastapi import APIRouter
from sqlalchemy.orm import Session
from info_handler import engine
from models.direct_remote_id import DjiMessage
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class DjiMessageDTO(BaseModel):
    id: int
    message_type: int
    version: int
    sender_id: str
    received_at: datetime

    serial_number: str | None
    dji_longitude: float | None
    dji_latitude: float | None
    dji_height: float | None
    dji_x_speed: float | None
    dji_y_speed: float | None
    dji_yaw: float | None
    dji_pilot_latitude: float | None
    dji_pilot_longitude: float | None

    
    class Config:
        from_attributes = True

@router.get("/api/dji/all", response_model=list[DjiMessageDTO], description="Get all DJI messages")
def get_basic_id_messages(sender_id: str = None) -> list[DjiMessageDTO]:
    with Session(engine) as session:
        query = session.query(DjiMessage)
        if sender_id:
            query = query.filter(DjiMessage.sender_id == sender_id)
        
        query = query.order_by(DjiMessage.received_at.desc())
        messages = query.all()
        return messages