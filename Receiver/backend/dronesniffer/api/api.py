from fastapi import FastAPI, WebSocket
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from ws_manager import create_manager
from api.ads_stan_api import router as ads_stan_api
from api.dji_api import router as dji_api
from api.drone_api import router as drone_api
from api.settings_api import init_router as settings_init


# Include vendor specific apis
def app(sniff_manager):
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

    app.include_router(drone_api, prefix="/api", tags=["Vendor Agnostic API"])
    app.include_router(dji_api, prefix="/api/dji", tags=["DJI API"])
    app.include_router(ads_stan_api, prefix="/api/ads_stan", tags=["ADS-STAN API"])
    app.include_router(settings_init(sniff_manager), prefix="/api", tags=["Settings API"])

    # needs to be last because it's a catch all
    app.mount("/", StaticFiles(directory="./frontend/dist/"), name="static")

    return app
