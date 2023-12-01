import logging
from typing import TYPE_CHECKING, Tuple
from urllib.parse import parse_qs

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
        self._siopv2_handler = hs.get_siopv2_handler()
        self.store = hs.get_datastores().main

    async def on_POST(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if not await self.store.validate_vp_session(sid, "created"):
            return 400, {"message": "Bad Request"}

        try:
            content_bytes = request.content.read()
            content = parse_qs(content_bytes.decode("utf-8"))
            expected_content_type = "application/x-www-form-urlencoded"
            if (
                request.requestHeaders.getRawHeaders("Content-Type")
                != expected_content_type
            ):
                return 400, {"message": "Bad Request"}
            # todo: validate vp_token
        except Exception:
            return 400, {"message": "Bad Request"}

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpResponse(hs).register(http_server)
