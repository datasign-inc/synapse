import logging
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class HandleSIOPv2Jwks(RestServlet):
    PATTERNS = client_patterns("/siopv2_jwks$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self._ro_signer = hs.get_oid4vc_request_object_signer()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self._ro_signer.setup_signing_key("kid1")

        response_data = {"keys": [self._ro_signer.as_dict()]}

        return 200, response_data


def register_servlets(hs, http_server):
    HandleSIOPv2Jwks(hs).register(http_server)
