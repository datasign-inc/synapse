import logging
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class HandleVpJwks(RestServlet):
    PATTERNS = client_patterns("/vp_jwks$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.jwt_signing_key = None

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if self.jwt_signing_key is None:
            key = await self.store.lookup_rsa_key("kid1")
            if key is None:
                # todo: generate rsa key
                pass

        # todo: Support for non-RSA keys
        response_data = {
            "keys": [
                {
                    "kty": key["kty"],
                    "n": key["n"],
                    "e": key["e"],
                }
            ]
        }

        return 200, response_data


def register_servlets(hs, http_server):
    HandleVpJwks(hs).register(http_server)
