"""Bluetooth Low Energy reception for ASTM Remote ID advertisements.

The scanner uses the operating system's BlueZ stack through Bleak.  It does not
put an adapter in monitor mode and never connects to advertising devices.
"""

import asyncio
import logging
from threading import Event, Thread
from typing import Callable
from uuid import UUID


LOG = logging.getLogger(__name__)

ASTM_REMOTE_ID_SERVICE_UUID = UUID("0000fffa-0000-1000-8000-00805f9b34fb")
OPEN_DRONE_ID_APPLICATION_CODE = 0x0D


def is_remote_id_service(uuid: str) -> bool:
    """Return whether a BLE service-data UUID is the ASTM Remote ID UUID."""
    try:
        return UUID(str(uuid)) == ASTM_REMOTE_ID_SERVICE_UUID
    except (TypeError, ValueError):
        return False


class BleRemoteIdSniffer:
    """Runs one passive BLE scanner for a BlueZ adapter (for example ``hci0``)."""

    def __init__(self, adapter: str, on_advertisement: Callable[[str, bytes], None]) -> None:
        self.adapter = adapter
        self.on_advertisement = on_advertisement
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        self._stop_event.clear()
        self._thread = Thread(target=self._run, name=f"ble-remote-id-{self.adapter}", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        try:
            asyncio.run(self._scan())
        except Exception:
            LOG.exception("BLE Remote ID scanner on %s stopped unexpectedly", self.adapter)

    async def _scan(self) -> None:
        # Import lazily so file replay and Wi-Fi-only use do not require a
        # functioning BlueZ installation during application startup.
        from bleak import BleakScanner

        scanner = BleakScanner(detection_callback=self._on_detection, adapter=self.adapter)
        LOG.info("Starting BLE Remote ID scanner on %s", self.adapter)
        await scanner.start()
        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(0.2)
        finally:
            await scanner.stop()
            LOG.info("Stopped BLE Remote ID scanner on %s", self.adapter)

    def _on_detection(self, device, advertisement_data) -> None:
        for service_uuid, data in advertisement_data.service_data.items():
            if not is_remote_id_service(service_uuid):
                continue
            if data and data[0] == OPEN_DRONE_ID_APPLICATION_CODE:
                self.on_advertisement(device.address, bytes(data))

