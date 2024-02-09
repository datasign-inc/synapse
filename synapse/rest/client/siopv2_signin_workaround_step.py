import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import RedirectException

from synapse.api.constants import SIOPv2SessionStatus
from synapse.http.server import HttpServer, respond_with_html
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


# todo: use DirectServeHtmlResource
class HandleSIOPv2SigninDummyStep(RestServlet):
    PATTERNS = client_patterns("/siopv2_signin_workaround_step/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self._siopv2_handler = hs.get_siopv2_handler()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:

        if not await self.store.validate_siopv2_session(
            sid, SIOPv2SessionStatus.POSTED
        ):
            logger.warning("Invalid session ID: %s", sid)
            return 400, {"message": "Bad Request"}

        html = await self.store.lookup_siopv2_signin_html(sid)

        if html is None or html == "":
            logger.warning("No HTML found for session ID: %s", sid)

        respond_with_html(request, 200, html)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleSIOPv2SigninDummyStep(hs).register(http_server)

