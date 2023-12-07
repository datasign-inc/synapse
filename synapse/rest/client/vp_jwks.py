import logging
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpJwks(RestServlet):
    PATTERNS = client_patterns("/vp_jwks$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._ro_signer = hs.get_oid4vc_request_object_signer()
        self.ro_signing_kid = self.hs.config.server.request_object_signing_kid

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self._ro_signer.setup_signing_key(self.ro_signing_kid)

        response_data = {"keys": [self._ro_signer.as_dict()]}
        return 200, response_data


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpJwks(hs).register(http_server)
