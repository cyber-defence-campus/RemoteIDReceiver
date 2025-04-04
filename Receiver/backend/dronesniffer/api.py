from datetime import datetime, timedelta
from typing import Generator

from fastapi import FastAPI, WebSocket
from scapy.interfaces import get_if_list
from sqlalchemy.orm import aliased
from sqlmodel import Session, func, select
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from info_handler import engine
from models import DroneDto, Position, RemoteId, HistoryDto
from settings import get_settings, save_settings, Settings
from ws_manager import create_manager

app = FastAPI()


@app.get("/")
def read_root() -> RedirectResponse:
    """
    Redirects to index.html.
    """
    return RedirectResponse(url="/index.html")


@app.websocket("/ws")
async def ws(ws: WebSocket) -> None:
    """
    Accepts new WebSocket connections and handles them as long as they are connected.

    Args:
        ws (WebSocket): The new WebSocket connection.
    """
    await ws.accept()
    manager = create_manager(ws)
    connected = True
    while connected:
        connected = await manager.handle_next_message()


def to_drone_dto(data: RemoteId) -> DroneDto:
    """
    Maps RemoteId to a DroneDto.

    Args:
        data (RemoteId): The RemoteId.

    Returns:
        DroneDto: Data Transfer Object with drone data.
    """
    return DroneDto(
        serial_number=f"{data.serial_number}",
        position=Position(lat=data.lat, lng=data.lng),
        pilot_position=Position(lat=data.pilot_lat, lng=data.pilot_lng) if data.pilot_lat and data.pilot_lng else None,
        home_position=Position(lat=data.home_lat, lng=data.home_lng) if data.home_lat and data.home_lng else None,
        rotation=data.yaw,
        altitude=data.altitude,
        height=data.height,
        x_speed=data.x_speed,
        y_speed=data.y_speed,
        z_speed=data.z_speed,
        spoofed=data.spoofed,
    )


def get_activity_offset() -> timedelta:
    """
    Fetches and returns activity offset from settings.

    Returns:
        timedelta: Current activity offset in minutes setting as timedelta.
    """
    settings = get_settings()
    return timedelta(minutes=settings.activity_offset_in_m)


def get_drones(only_active=True) -> list[DroneDto]:
    """
    Returns all or all active drones depending on the parameter at their latest timestamp.
    """
    with Session(engine) as session:
        # Subquery to get the latest timestamp for every drone.
        # If only_active is True, it will only consider timestamps within the activity offset.
        subquery = select(
            RemoteId.serial_number,
            func.max(RemoteId.timestamp).label("max_timestamp")
        ).where(
            RemoteId.timestamp >= (datetime.now() - get_activity_offset()) if only_active else True
        ).group_by(RemoteId.serial_number).subquery()
        
        # Join the subquery with RemoteId to get the full objects
        query = select(RemoteId).join(
            subquery,
            (RemoteId.serial_number == subquery.c.serial_number) & 
            (RemoteId.timestamp == subquery.c.max_timestamp)
        ).order_by(RemoteId.serial_number)
        
        return list(map(
            to_drone_dto,
            session.exec(query).all()
        ))


@app.get("/api/drones/active", response_model=list[DroneDto])
def get_active_drones() -> list[DroneDto]:
    """
    Returns all active drones as DroneDto.
    """
    return get_drones()


@app.get("/api/drones/all", response_model=list[DroneDto])
def get_all_drones() -> list[DroneDto]:
    """
    Returns all drones that have ever been found.
    """
    return get_drones(only_active=False)


def get_positions(drone: RemoteId) -> tuple[Position, Position, Position]:
    """
    Extracts the drone (first), pilot (second) and home (third) position of that drone packet.

    Args:
        drone (RemoteId): The RemoteId.

    Returns:
        (Position, Position, Position): Positions of drone, pilot and home.
    """
    return (
        Position(lat=drone.lat, lng=drone.lng) if drone.lat and drone.lng else None,
        Position(lat=drone.pilot_lat, lng=drone.pilot_lng) if drone.pilot_lat and drone.pilot_lng else None,
        Position(lat=drone.home_lat, lng=drone.home_lng) if drone.home_lat and drone.home_lng else None
    )


def get_drone_packets_query(serial_number: str) -> Generator:
    """
    Returns all flight info packets with that serial_number.

    Args:
        serial_number (str): Serial number.
    """
    query = select(RemoteId) \
        .where(RemoteId.serial_number == serial_number) \
        .order_by(RemoteId.timestamp.asc())
    with Session(engine) as session:
        for drone in session.exec(query):
            yield drone


def to_history_dto(drone: RemoteId) -> HistoryDto:
    """
    Maps DroneFlightInfoPacket data onto HistoryDto.

    Args:
        drone (RemoteId): The RemoteId.

    Returns:
        HistoryDto: Returns history of a flight.
    """
    pos, pilot_pos, home_pos = get_positions(drone)
    return HistoryDto(
        timestamp=drone.timestamp,
        pos=pos,
        pilot_pos=pilot_pos,
        home_pos=home_pos
    )


@app.get("/api/drones/{serial_number}/history", response_model=list[HistoryDto])
def get_history(serial_number: str) -> list[HistoryDto]:
    """
    Returns the history of the drone with that serial_number.

    Args:
        serial_number (str): Drone serial number.

    Returns:
        list[HistoryDto]: List of past flights.
    """
    path: list[HistoryDto] = []
    latest_timestamp = None
    for drone in get_drone_packets_query(serial_number):
        # if the that package was out of range of the next, it is considered old and is ignored
        if latest_timestamp and latest_timestamp + get_activity_offset() < drone.timestamp:
            path = []
        latest_timestamp = drone.timestamp

        path.append(to_history_dto(drone))

    return path


@app.get("/api/drones/{serial_number}/flights", response_model=list[datetime])
def get_flights(serial_number: str) -> list[datetime]:
    """
    Returns the start time of all flights for the drone with that serial_number.

    Args:
        serial_number (str): Drone serial number.

    Returns:
        list[datetime]: List of flight start times.
    """
    timestamps = []
    latest_timestamp = None
    for drone in get_drone_packets_query(serial_number):
        # if no latest_timestamp exists or the new timestamp is out of range, consider it as new flight
        if latest_timestamp is None or latest_timestamp + get_activity_offset() < drone.timestamp:
            timestamps.append(drone.timestamp)
        latest_timestamp = drone.timestamp

    return timestamps


@app.get("/api/drones/{serial_number}/flights/{flight}", response_model=list[HistoryDto])
def get_flight_history(serial_number: str, flight: datetime) -> list[HistoryDto]:
    """
    Returns the history of a specific flight by the drone with that serial_number.

    Args:
        serial_number (str): Drone serial number.
        flight (datetime): start time.

    Returns:
        list[HistoryDto]: List of a flight history.
    """
    path: list[HistoryDto] = []
    latest_timestamp = None
    for drone in get_drone_packets_query(serial_number):
        # if we haven't reached the correct flight, skip
        if latest_timestamp is None and drone.timestamp != flight:
            continue

        # if we reach timestamps past the flight, end loop
        if latest_timestamp and latest_timestamp + get_activity_offset() < drone.timestamp:
            break

        latest_timestamp = drone.timestamp
        path.append(to_history_dto(drone))

    return path


@app.get("/api/settings", response_model=Settings)
def get_api_settings() -> Settings:
    """
    Returns the current settings.
    """
    return get_settings()


@app.post("/api/settings", response_model=Settings)
def post_api_settings(settings: Settings) -> Settings:
    """
    Saves new settings.

    Args:
        settings (Settings): Settings to save.

    Returns:
        Settings: Saved settings.
    """
    save_settings(settings)
    sniff_manager.set_sniffing_interfaces(settings.interfaces)
    return settings


@app.get("/api/settings/interfaces", response_model=list[str])
def get_interfaces() -> list[str]:
    """
    Returns all interfaces found on the device.
    """
    return get_if_list()


# needs to be last because it's a catch all
app.mount("/", StaticFiles(directory="./frontend/"), name="static")
