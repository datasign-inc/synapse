import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import VPSessionStatus
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpResponse(RestServlet):
    PATTERNS = client_patterns("/vp_response/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._auth = hs.get_auth()
        self._vp_handler = hs.get_verifiable_presentation_handler()

    async def on_POST(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if not await self.store.validate_vp_session(sid, VPSessionStatus.CREATED):
            logger.warning("Invalid session ID: %s", sid)
            return 400, {"message": "Bad Request"}

        token_value, claims = await self._vp_handler.handle_vp_response(request, sid)
        await self._vp_handler.register_claims(sid, token_value, claims)

        return 200, {"message": "Registration ended successfully"}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpResponse(hs).register(http_server)
