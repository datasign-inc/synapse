import logging
import urllib.parse
from typing import Tuple

from authlib.jose import JsonWebKey, jwt

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import add_query_param_to_url, random_string

logger = logging.getLogger(__name__)


class HandleSIOPv2Request(RestServlet):
    PATTERNS = client_patterns("/siopv2_request$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.jwt_signing_key = None

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        siopv2_sid = request.args.get(b"sv2sid", [b""])[0].decode("utf-8")

        if siopv2_sid == "" or not await self.store.validate_siopv2_session(
            siopv2_sid, "created"
        ):
            return 400, {"message": "Bad Request"}

        base_url = self.hs.config.server.public_baseurl
        redirect_uri = add_query_param_to_url(
            urllib.parse.urljoin(base_url, "/_matrix/client/v3/siopv2_response"),
            "sv2sid",
            siopv2_sid,
        )

        issued_nonce = await self.store.lookup_ro_nonce(siopv2_sid)
        if issued_nonce is None or issued_nonce == "":
            nonce = random_string(8)
            await self.store.register_ro_nonce(siopv2_sid, nonce)
        else:
            nonce = issued_nonce

        if self.jwt_signing_key is None:
            key = await self.store.lookup_rsa_key("kid1")
            if key is None:
                pass
                # todo: generate rsa key
            else:
                self.jwt_signing_key = JsonWebKey.import_key(key)

        payload = {
            "iss": redirect_uri,
            "client_id": redirect_uri,
            "redirect_uri": redirect_uri,
            "nonce": nonce,
            "response_type": "id_token",
            "scope": "openid",
            "aud": "https://self-issued.me/v2",
        }

        ro_jwt = jwt.encode({"alg": "RS256"}, payload, self.jwt_signing_key)

        return 200, ro_jwt


def register_servlets(hs, http_server):
    HandleSIOPv2Request(hs).register(http_server)
