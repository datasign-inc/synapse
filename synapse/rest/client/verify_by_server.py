import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import VPType
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVerifyByServer(RestServlet):
    PATTERNS = client_patterns(
        "/verify_by_server/(?P<vp_type>(%s))$" % "|".join([x.value for x in VPType])
    )

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, vp_type: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        logger.info("user_id %s" % user_id)

        vp_data = await self.store.lookup_vp_data(user_id, VPType(vp_type))

        response_data = {
            # todo: add more check
            "verification_status": "ok"
            if len(vp_data) > 0
            else "ng"
        }

        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVerifyByServer(hs).register(http_server)
