from fastapi import APIRouter
from scapy.interfaces import get_if_list
from settings import get_settings, save_settings, Settings
from sniffers import get_bluetooth_interfaces

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
        sniff_manager.set_ble_interfaces(settings.ble_interfaces)
        return settings


    @router.get("/settings/interfaces", response_model=list[str])
    def get_interfaces() -> list[str]:
        """
        Returns all interfaces found on the device.
        """
        return get_if_list()


    @router.get("/settings/bluetooth-interfaces", response_model=list[str])
    def get_bluetooth_adapters() -> list[str]:
        """Return local BlueZ adapters that can be selected for BLE scanning."""
        return get_bluetooth_interfaces()
    
    return router
