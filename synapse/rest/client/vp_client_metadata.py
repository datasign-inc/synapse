import logging
import urllib.parse
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpClientMetadata(RestServlet):
    PATTERNS = client_patterns("/vp_client_metadata/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._ro_signer = hs.get_oid4vc_request_object_signer()
        self.ro_signing_kid = self.hs.config.server.request_object_signing_kid

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if not await self.store.validate_vp_session(sid, "created"):
            return 400, {"message": "Bad Request"}

        await self._ro_signer.setup_signing_key(self.ro_signing_kid)
        base_url = self.hs.config.server.public_baseurl

        response_data = {
            "jwks_uri": urllib.parse.urljoin(base_url, "/_matrix/client/v3/vp_jwks"),
            "request_object_signing_alg": self._ro_signer.decide_alg(),
        }

        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpClientMetadata(hs).register(http_server)
