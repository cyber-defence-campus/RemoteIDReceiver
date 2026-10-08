from fastapi import APIRouter
from scapy.config import conf
from scapy.interfaces import get_if_list
from settings import get_settings, save_settings, Settings

router = APIRouter()

def init_router(sniff_manager):

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

        Reloads Scapy's cached interface list first so adapters that were
        plugged in after the process started are included.
        """
        try:
            conf.ifaces.reload()
        except Exception:
            # Fall back to the cached list rather than failing the endpoint.
            pass
        return get_if_list()
    
    return router
