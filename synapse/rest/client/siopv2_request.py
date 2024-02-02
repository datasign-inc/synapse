import logging
import urllib.parse
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import SIOPv2SessionStatus
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class HandleSIOPv2Request(RestServlet):
    PATTERNS = client_patterns("/siopv2_request/(?P<sid>[^/]*)$")

    def __init__(self, hs: "HomeServer") -> None:
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.ro_signing_kid = self.hs.config.server.request_object_signing_kid
        self._ro_signer = hs.get_oid4vc_request_object_signer()

    async def on_GET(self, request: SynapseRequest, sid: str) -> Tuple[int, JsonDict]:
        logger.info("Checking session SIOPv2 Request ID: %s\n" % sid)
        if not await self.store.validate_siopv2_session(
            sid, SIOPv2SessionStatus.CREATED
        ):
            logger.warning("Invalid session ID: %s", sid)
            return 400, {"message": "Bad Request"}

        base_url = self.hs.config.server.public_baseurl

        redirect_uri = urllib.parse.urljoin(
            base_url, "/".join(["/_matrix/client/v3/siopv2_response", sid])
        )

        issued_nonce = await self.store.lookup_siopv2_ro_nonce(sid)
        if issued_nonce is None or issued_nonce == "":
            nonce = random_string(8)
            await self.store.register_siopv2_ro_nonce(sid, nonce)
        else:
            nonce = issued_nonce

        await self._ro_signer.setup_signing_key(self.ro_signing_kid)

        payload = {
            "iss": redirect_uri,

            # "client_id": redirect_uri,
            # WIP ######################
            "client_id": "https://ownd-project.com:8008/",
            ############################

            "redirect_uri": redirect_uri,
            "nonce": nonce,
            "response_type": "id_token",
            "response_mode": "post",# todo: support same-device flow
            "scope": "openid",
            "aud": "https://self-issued.me/v2",
        }

        ro_jwt = self._ro_signer.sign({}, payload)

        return 200, ro_jwt


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    HandleSIOPv2Request(hs).register(http_server)
