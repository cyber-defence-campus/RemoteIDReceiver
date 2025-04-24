from fastapi import APIRouter
from datetime import datetime, timedelta
from models import DroneDto
from services.drone_service_ads import DroneServiceAds
from services.drone_service_dji import DroneServiceDji
from settings import get_settings
from info_handler import engine

router = APIRouter()

drone_serive_ads = DroneServiceAds(engine)
drone_service_dji = DroneServiceDji(engine)

def get_drone_service(sender_id: str): 
    if drone_serive_ads.exists(sender_id):
        return drone_serive_ads
    elif drone_service_dji.exists(sender_id):
        return drone_service_dji
    else:
        raise ValueError(f"Drone with sender_id {sender_id} not found in either service.")

def get_activity_offset() -> timedelta:
    settings = get_settings()
    return timedelta(minutes=settings.activity_offset_in_m)

@router.get("/drones/active", response_model=list[str])
def get_active_drones() -> list[str]:
    active_ads_stan = drone_serive_ads.get_active_drone_senders()
    active_dji = drone_service_dji.get_active_drone_senders()
    return list(set(active_ads_stan) | set(active_dji))

@router.get("/drones/all", response_model=list[str])
def get_all_drones() -> list[str]:
    all_ads_stan = drone_serive_ads.get_all_drone_senders()
    all_dji = drone_service_dji.get_all_drone_senders()
    return list(set(all_ads_stan) | set(all_dji))

@router.get("/drones/{sender_id}", response_model=DroneDto)
def get_drone(sender_id: str):
    service = get_drone_service(sender_id)
    return service.get_drone_state(sender_id)

@router.get("/drones/{sender_id}/flights", response_model=list[datetime])
def get_flights(sender_id: str) -> list[datetime]:
    service = get_drone_service(sender_id)
    return service.get_drone_flight_start_times(sender_id, get_activity_offset())

@router.get("/drones/{sender_id}/flights/{flight}", response_model=list[dict])
def get_flight_history(sender_id: str, flight: datetime) -> list[dict]:
    service = get_drone_service(sender_id)
    return service.get_flight_history(sender_id, flight, get_activity_offset()) 