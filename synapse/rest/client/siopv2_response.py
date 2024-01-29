import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import RedirectException

from synapse.api.constants import SIOPv2SessionStatus
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# todo: use DirectServeHtmlResource
class HandleSIOPv2Response(RestServlet):
    PATTERNS = client_patterns("/siopv2_response/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self._siopv2_handler = hs.get_siopv2_handler()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:

        logger.info("Dummy callback is called. It appears that the login token was issued successfully.")

        response_data = {
            "message": "Success!!",
        }

        return 200, response_data  # 応答を返す

    async def on_POST(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        logger.warning("Checking session SIOPv2 Response ID: %s", sid)
        if not await self.store.validate_siopv2_session(
            sid, SIOPv2SessionStatus.CREATED
        ):
            return 400, {"message": "Bad Request"}

        try:
            await self._siopv2_handler.handle_siopv2_response(request, sid)
        except RedirectException as e:
            request.setHeader(b"location", e.location)
            request.cookies.extend(e.cookies)
            return 302, {"Location": str(e.location)}

        response_data = {"message": "New endpoint data received.", "data": ""}
        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleSIOPv2Response(hs).register(http_server)
