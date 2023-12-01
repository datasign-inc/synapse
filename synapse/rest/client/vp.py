import logging
import urllib.parse
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)


class HandleVpInitiation(RestServlet):
    PATTERNS = client_patterns("/vp/(?P<vp_type>[^/]*)$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.base_url = self.hs.config.server.public_baseurl

    async def on_GET(
        self, request: SynapseRequest, vp_type: str
    ) -> Tuple[int, JsonDict]:
        # todo: Make type_domain generally usable.
        type_domain = ("ageOver13", "affiliation")

        if vp_type not in type_domain:
            return 400, {"message": "Bad Request"}

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


def register_servlets(hs, http_server):
    HandleVpInitiation(hs).register(http_server)
