from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import VPSessionStatus
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


class HandleVPPolling(RestServlet):
    PATTERNS = client_patterns("/vp_polling/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self._auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)

        if not await self.store.validate_vp_session(sid, VPSessionStatus.POSTED):
            return 400, {"message": "Bad Request"}

        await self.store.invalidate_vp_session(sid)
        response_data = {"message": "ok"}

        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVPPolling(hs).register(http_server)
