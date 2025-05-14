from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

### 
# ADS-STAN Messages
###

class BasicIdMessage(Base):
    """Basic ID Message (type 0x0)"""
    __tablename__ = 'basic_id_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x0)
    version = Column(Integer, nullable=False, default=0x0)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    id_type = Column(Integer, nullable=True)
    ua_type = Column(Integer, nullable=True)
    uas_id = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<BasicIdMessage(sender_id={self.sender_id}, uas_id={self.uas_id})>"

class LocationMessage(Base):
    """Location Vector Message (type 0x1)"""
    __tablename__ = 'location_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x1)
    version = Column(Integer, nullable=False, default=0x0)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    operational_status = Column(Integer, nullable=True)
    is_reserved = Column(Boolean, nullable=True)
    height_type = Column(Integer, nullable=True)
    track_direction = Column(Integer, nullable=True)
    speed = Column(Integer, nullable=True)
    vertical_speed = Column(Integer, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    altitude_barometric = Column(Integer, nullable=True)
    altitude_geodetic = Column(Integer, nullable=True)
    height_above_takeoff = Column(Integer, nullable=True)
    accuracy_horizontal = Column(Integer, nullable=True)
    accuracy_vertical = Column(Integer, nullable=True)
    accuracy_speed = Column(Integer, nullable=True)
    accuracy_barometric_altitude = Column(Integer, nullable=True)
    accuracy_timestamp = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<LocationMessage(sender_id={self.sender_id}, lat={self.latitude}, lon={self.longitude})>"

class SelfIdMessage(Base):
    """Self ID Message (type 0x3)"""
    __tablename__ = 'self_id_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x3)
    version = Column(Integer, nullable=False, default=0x0)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    description_type = Column(Integer, nullable=True)
    description = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<SelfIdMessage(sender_id={self.sender_id}, description={self.description})>"

class SystemMessage(Base):
    """System Message (type 0x4)"""
    __tablename__ = 'system_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x4)
    version = Column(Integer, nullable=False, default=0x0)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    classification_type = Column(Integer, nullable=True)
    location_source = Column(Integer, nullable=True)
    pilot_latitude = Column(Float, nullable=True)
    pilot_longitude = Column(Float, nullable=True)
    area_count = Column(Integer, nullable=True)
    area_radius = Column(Integer, nullable=True)
    area_ceiling = Column(Integer, nullable=True)
    area_floor = Column(Integer, nullable=True)
    ua_category = Column(Integer, nullable=True)
    ua_class = Column(Integer, nullable=True)
    pilot_geodetic_altitude = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<SystemMessage(sender_id={self.sender_id}, ua_category={self.ua_category}, ua_class={self.ua_class})>"

class OperatorMessage(Base):
    """Operator ID Message (type 0x5)"""
    __tablename__ = 'operator_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x5)
    version = Column(Integer, nullable=False, default=0x0)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    operator_id_type = Column(Integer, nullable=True)
    operator_id = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<OperatorMessage(sender_id={self.sender_id}, operator_id={self.operator_id})>"

###
# DJI Messages
###
class DjiMessage(Base):
    """DJI Message """
    __tablename__ = 'dji_messages'

    id = Column(Integer, primary_key=True)
    message_type = Column(Integer, nullable=False, default=0x6)
    version = Column(Integer, nullable=False)  # 0x0-0xF
    sender_id = Column(String(255), nullable=False, index=True)  # Who sent the message (MAC-Address for wifi)
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))  # When we received the message

    serial_number = Column(String(255), nullable=True)
    dji_longitude = Column(Float, nullable=True)
    dji_latitude = Column(Float, nullable=True)
    dji_height = Column(Float, nullable=True)
    dji_x_speed = Column(Float, nullable=True)
    dji_y_speed = Column(Float, nullable=True)
    dji_yaw = Column(Float, nullable=True)
    dji_pilot_latitude = Column(Float, nullable=True)
    dji_pilot_longitude = Column(Float, nullable=True)

    def __repr__(self):
        return f"<DjiMessage(sender_id={self.sender_id}, serial_number={self.serial_number})>"
