import logging
import urllib.parse
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import random_string
from synapse.api.constants import VPType

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpInitiation(RestServlet):
    PATTERNS = client_patterns(
        "/vp/(?P<vp_type>(%s))$" % "|".join([x.value for x in VPType])
    )

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.base_url = self.hs.config.server.public_baseurl

    async def on_GET(
        self, request: SynapseRequest, vp_type: str
    ) -> Tuple[int, JsonDict]:
        sid = random_string(32)
        ro_nonce = random_string(8)
        await self.store.register_vp_session(sid, vp_type, ro_nonce)

        client_id = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_response", sid])
        )

        request_uri = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_request", sid])
        )

        polling_uri = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_polling", sid])
        )

        response_data = {
            "client_id": client_id,
            "request_uri": request_uri,
            "polling_uri": polling_uri,
        }

        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpInitiation(hs).register(http_server)
