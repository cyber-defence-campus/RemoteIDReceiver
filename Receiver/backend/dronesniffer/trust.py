"""
Spoofing checks for ASTM F3411 Remote ID transmitters, done by the remoteid package
(https://pypi.org/project/remoteid/).

Every Wi-Fi frame that carries Remote ID is fed to one remoteid.Tracker, which compares it with what the
same transmitter sent before: position jumps and speeds, message counters, the transmitter's clocks, and the
frame formats of known spoofing tools. The result per MAC address is a verdict ("plausible", "suspicious" or
"spoofed") with the reasons behind it. DRIP signatures ("authenticated") need trusted keys and a UTC clock,
which are not configured here.

If remoteid is not installed (no wheel for the platform), observe() does nothing and verdict() returns None.
"""
import logging
import threading
from typing import Optional

from scapy.packet import Packet

LOG = logging.getLogger(__name__)

try:
    import remoteid
except ImportError:
    remoteid = None
    LOG.warning("remoteid is not installed, Remote ID spoofing checks are off")

# Forget a transmitter after the same time a drone counts as active (DroneService._active_drone_max_age).
TIMEOUT_MS = 60_000

_lock = threading.Lock()  # packets are processed by many worker threads
_tracker = remoteid.Tracker(timeout_ms=TIMEOUT_MS) if remoteid else None


def observe(packet: Packet) -> None:
    """
    Feed one received Wi-Fi frame that carries Remote ID (with or without its RadioTap header).

    The frame's capture time (packet.time) is the receive time, so captures replayed from a file are checked
    with their original timing.
    """
    if _tracker is None:
        return
    rssi = getattr(packet, "dBm_AntSignal", None)
    try:
        with _lock:
            _tracker.ingest(bytes(packet), now_ms=int(float(packet.time) * 1000), rssi=rssi)
    except ValueError as e:
        LOG.debug(f"remoteid could not read frame: {e}")


def verdict(sender_id: str) -> Optional["remoteid.Verdict"]:
    """
    The current verdict for a transmitter (MAC address), or None if it was not heard in the last
    TIMEOUT_MS, none of its frames could be read, sender_id is not a MAC address, or remoteid is not installed.
    """
    if _tracker is None:
        return None
    with _lock:
        try:
            found = _tracker.get(sender_id)
        except (KeyError, ValueError):  # not heard, or not a MAC address
            return None
    # A transmitter whose frames remoteid could not read has no evidence either way
    return found if found.frames > 0 else None


def reset() -> None:
    """Forget every transmitter."""
    global _tracker
    if remoteid is not None:
        with _lock:
            _tracker = remoteid.Tracker(timeout_ms=TIMEOUT_MS)
