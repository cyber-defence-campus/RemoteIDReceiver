from fastapi import APIRouter
from scapy.interfaces import get_if_list
from settings import get_settings, save_settings, Settings

router = APIRouter()

@router.get("/settings", response_model=Settings)
def get_api_settings() -> Settings:
    """
    Returns the current settings.
    """
    return get_settings()


@router.post("/settings", response_model=Settings)
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


@router.get("/settings/interfaces", response_model=list[str])
def get_interfaces() -> list[str]:
    """
    Returns all interfaces found on the device.
    """
    return get_if_list() 