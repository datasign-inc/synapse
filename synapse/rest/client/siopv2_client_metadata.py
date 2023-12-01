import logging
import urllib.parse
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class HandleSIOPv2ClientMetadata(RestServlet):
    PATTERNS = client_patterns("/siopv2_client_metadata/(?P<sid>[^/]*)$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._ro_signer = hs.get_oid4vc_request_object_signer()

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if sid == "" or not await self.store.validate_siopv2_session(sid, "created"):
            return 400, {"message": "Bad Request"}

        await self._ro_signer.setup_signing_key("kid1")
        base_url = self.hs.config.server.public_baseurl

        response_data = {
            "redirect_uris": [
                urllib.parse.urljoin(
                    base_url, "/".join(["/_matrix/client/v3/siopv2_response", sid])
                )
            ],
            "jwks_uri": urllib.parse.urljoin(
                base_url, "/_matrix/client/v3/siopv2_jwks"
            ),
            "request_object_signing_alg": self._ro_signer.decide_alg(),
        }

        return 200, response_data


def register_servlets(hs, http_server):
    HandleSIOPv2ClientMetadata(hs).register(http_server)
