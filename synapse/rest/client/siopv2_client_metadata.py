import logging
from synapse.http.servlet import RestServlet
from synapse.types import JsonDict
from synapse.http.server import HttpServer
from synapse.http.site import SynapseRequest
from typing import Tuple
from synapse.rest.client._base import client_patterns
from urllib.parse import parse_qs
from synapse.http import redact_uri
from synapse.api.errors import Codes
from http import HTTPStatus
from synapse.handlers.oidc import Token
import urllib.parse


import inspect
from synapse.util.stringutils import add_query_param_to_url
from typing import Any

logger = logging.getLogger(__name__)


class HandleSIOPv2ClientMetadata(RestServlet):
    PATTERNS = client_patterns("/siopv2_client_metadata$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        siopv2_sid = request.args.get(b'sv2sid', [b''])[0].decode('utf-8')

        if siopv2_sid == '' or not await self.store.validate_siopv2_session(siopv2_sid, "created"):
            return 400, {"message": "Bad Request"}

        base_url = self.hs.config.server.public_baseurl

        response_data = {
            "redirect_uris": [
                add_query_param_to_url(
                    urllib.parse.urljoin(base_url, "/_matrix/client/v3/siopv2_response"),
                    "sv2sid", siopv2_sid)
            ],
            "jwks_uri": urllib.parse.urljoin(base_url, "/_matrix/client/v3/siopv2_jwks"),
            "request_object_signing_alg": "RS256",
        }

        return 200, response_data


def register_servlets(hs, http_server):
    HandleSIOPv2ClientMetadata(hs).register(http_server)