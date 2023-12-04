import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import SIOPv2SessionStatus
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleSIOPv2Polling(RestServlet):
    PATTERNS = client_patterns("/siopv2_polling/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if not await self.store.validate_siopv2_session(
            sid, SIOPv2SessionStatus.POSTED
        ):
            return 400, {"message": "Bad Request"}

        value = await self.store.get_login_token_for_siopv2_sid(sid)
        if value is None:
            return 400, {"message": "Bad Request"}

        await self.store.invalidate_siopv2_session(sid)
        response_data = {"siopv2_sid": sid, "login_token": value}

        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleSIOPv2Polling(hs).register(http_server)
