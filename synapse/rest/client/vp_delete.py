import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import VPType
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpDelete(RestServlet):
    PATTERNS = client_patterns("/vp_delete$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self._auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        body = parse_json_object_from_request(request)
        vp_type = body.get("vp_type", None)
        num = body.get("num", None)

        if vp_type is None or num is None:
            return 400, {"message": "Bad Request"}

        await self.store.delete_vp_data(user_id, VPType(vp_type), num)

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpDelete(hs).register(http_server)
