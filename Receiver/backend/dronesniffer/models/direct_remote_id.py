from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

# Base for SQLAlchemy declarative mappings
Base = declarative_base()

# ---------------------------------------------------------------------------
# Abstract base class for all Remote ID message models                     
# ---------------------------------------------------------------------------
#
# Many of the message types share the same bookkeeping columns (primary key,
# protocol version, sender identifier and reception timestamp).  We keep them
# in one place so they only need to be maintained once and every model gets
# the identical definition.
# ---------------------------------------------------------------------------


class RemoteIdMessageBase(Base):
    """Abstract base that bundles columns common to all Remote ID messages."""

    __abstract__ = True  # SQLAlchemy should NOT create its own table for this

    # Primary key for every message table
    id = Column(Integer, primary_key=True)

    # All messages carry a protocol version (currently 0x0-0xF)
    version = Column(Integer, nullable=False, default=0x0)

    # MAC address (Wi-Fi) or other identifier of the transmitter
    sender_id = Column(String(255), nullable=False, index=True)

    # Timestamp when this message was received by the sniffer backend
    received_at = Column(DateTime, nullable=False, default=datetime.now(timezone.utc))

    # Every message has a numeric type.  Sub-classes set the proper constant in
    # their constructor so we declare the column once here.
    message_type = Column(Integer, nullable=False)

### 
# ADS-STAN Messages
###

# ---------------------------------------------------------------------------
# ADS-STAN Basic ID Message (type 0x0)
# ---------------------------------------------------------------------------

class BasicIdMessage(RemoteIdMessageBase):
    """Basic ID Message (type 0x0)"""
    __tablename__ = 'basic_id_messages'

    def __init__(self, **kwargs):
        # Ensure callers cannot override the fixed message type accidentally.
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0x0

    id_type = Column(Integer, nullable=True)
    ua_type = Column(Integer, nullable=True)
    uas_id = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<BasicIdMessage(sender_id={self.sender_id}, uas_id={self.uas_id})>"

# ---------------------------------------------------------------------------
# ADS-STAN Location/Vector Message (type 0x1)
# ---------------------------------------------------------------------------

class LocationMessage(RemoteIdMessageBase):
    """Location Vector Message (type 0x1)"""
    __tablename__ = 'location_messages'

    def __init__(self, **kwargs):
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0x1

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

# ---------------------------------------------------------------------------
# ADS-STAN Self ID Message (type 0x3)
# ---------------------------------------------------------------------------

class SelfIdMessage(RemoteIdMessageBase):
    """Self ID Message (type 0x3)"""
    __tablename__ = 'self_id_messages'

    def __init__(self, **kwargs):
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0x3

    description_type = Column(Integer, nullable=True)
    description = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<SelfIdMessage(sender_id={self.sender_id}, description={self.description})>"

# ---------------------------------------------------------------------------
# ADS-STAN System Message (type 0x4)
# ---------------------------------------------------------------------------

class SystemMessage(RemoteIdMessageBase):
    """System Message (type 0x4)"""
    __tablename__ = 'system_messages'

    def __init__(self, **kwargs):
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0x4

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

# ---------------------------------------------------------------------------
# ADS-STAN Operator ID Message (type 0x5)
# ---------------------------------------------------------------------------

class OperatorMessage(RemoteIdMessageBase):
    """Operator ID Message (type 0x5)"""
    __tablename__ = 'operator_messages'

    def __init__(self, **kwargs):
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0x5

    operator_id_type = Column(Integer, nullable=True)
    operator_id = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<OperatorMessage(sender_id={self.sender_id}, operator_id={self.operator_id})>"

###
# DJI Messages
###

# ---------------------------------------------------------------------------
# DJI proprietary Remote ID Message (mapped to type 0x6 for our purposes)
# ---------------------------------------------------------------------------

class DjiMessage(RemoteIdMessageBase):
    """DJI Message """
    __tablename__ = 'dji_messages'

    def __init__(self, **kwargs):
        kwargs.pop("message_type", None)
        super().__init__(**kwargs)
        self.message_type = 0xA

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
