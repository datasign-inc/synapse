import logging
import urllib.parse
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import VPSessionStatus
from synapse.handlers.vp_handler import make_required_descriptors
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleVpRequest(RestServlet):
    PATTERNS = client_patterns("/vp_request/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._auth = hs.get_auth()
        self._ro_signer = hs.get_oid4vc_request_object_signer()
        self.ro_signing_kid = self.hs.config.server.request_object_signing_kid
        self.base_url = self.hs.config.server.public_baseurl

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        if not await self.store.validate_vp_session(sid, VPSessionStatus.CREATED):
            logger.warning("Invalid session ID: %s", sid)
            return 400, {"message": "Bad Request"}

        await self._ro_signer.setup_signing_key(self.ro_signing_kid)

        vp_type = await self.store.lookup_vp_type(sid)
        ro_nonce = await self.store.lookup_vp_ro_nonce(sid)

        client_id = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_response", sid])
        )

        client_metadata_uri = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_client_metadata", sid])
        )

        input_descriptors, requirements = make_required_descriptors(vp_type)

        payload = {
            "client_id": client_id,
            "client_id_scheme": "x509_san_dns",
            "response_uri": client_id,
            "nonce": ro_nonce,
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "presentation_definition": {
                "id": sid,
                "input_descriptors": input_descriptors,
                "submission_requirements": requirements,
            },
            "client_metadata_uri": client_metadata_uri,
        }

        ro_jwt = self._ro_signer.sign({}, payload)
        return 200, ro_jwt


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleVpRequest(hs).register(http_server)
