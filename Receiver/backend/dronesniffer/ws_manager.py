import asyncio

from fastapi import WebSocket
from models.dtomodels import MinimalDroneDto
__all__ = ["create_manager", "broadcast"]


class ConnectionManager:
    """
    Handles the connection for a specific WebSocket connection.
    """

    def __init__(self, ws: WebSocket) -> None:
        """
        Args:
            ws: WebSocket connection.
        """
        self._ws = ws
        self._message_queue = asyncio.Queue()

    def broadcast(self, remote_id) -> None:
        """
        Broadcasts remote_id info to the websocket connection.

        Args:
            remote_id (RemoteId): RemoteId to broadcast.
        """
        from api import to_drone_dto
        msg = to_drone_dto(remote_id).dict()
        self._message_queue.put_nowait(msg)

    async def handle_next_message(self) -> bool:
        """
        Waits for the next message and sends it to the client.

        Returns:
            bool: True when the WS is still connected, False when it's disconnected.
        """
        msg = await self._message_queue.get()
        try:
            await self._ws.send_json(msg)
            return True
        except:
            _managers.remove(self)
            return False


_managers: list[ConnectionManager] = []


def create_manager(ws: WebSocket) -> ConnectionManager:
    """
    Creates a ConnectionManager for this WebSocket.

    Args:
        ws (WebSocket): The new WebSocket connection.

    Returns:
        ConnectionManager: New manager for this WebSocket connection.
    """
    manager = ConnectionManager(ws)
    _managers.append(manager)
    return manager


def broadcast(remote_id: MinimalDroneDto) -> None:
    """
    Broadcasts remote_id to all WS connections.

    Args:
        remote_id (RemoteId): The RemoteId.
    """
    for manager in _managers:

        manager.broadcast(remote_id)
