import logging
import urllib.parse
from typing import Tuple

from authlib.jose import JsonWebKey, jwt

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import add_query_param_to_url

logger = logging.getLogger(__name__)


def make_input_descriptors(vp_type: str):
    if vp_type == "ageOver13":
        return [
            {
                "id": "age_over_13",
                "name": "年齢が13以上であることを確認します",
                "purpose": "Matrixの機能を全て利用するためには、年齢の確認が必要です",
                "constraints": {"fields": [{"path": ["$.credentialSubject.isOver13"]}]},
            }
        ]
    elif vp_type == "affiliation":
        return [
            {
                "id": "affiliation",
                "name": "所属情報を確認します",
                "purpose": "Matrix利用者に自身の所属を提示することができるようになります",
                "constraints": {
                    "fields": [{"path": ["$.credentialSubject.affiliation"]}]
                },
            }
        ]
    else:
        # todo: raise an error
        pass


class HandleVpRequest(RestServlet):
    PATTERNS = client_patterns("/vp_request$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.jwt_signing_key = None
        self.base_url = self.hs.config.server.public_baseurl

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        vpsid = request.args.get(b"vpsid", [b""])[0].decode("utf-8")

        if vpsid == "" or not await self.store.validate_vp_session(vpsid, "created"):
            return 400, {"message": "Bad Request"}

        client_id = add_query_param_to_url(
            urllib.parse.urljoin(self.base_url, "/_matrix/client/v3/vp_response"),
            "vpsid",
            vpsid,
        )

        if self.jwt_signing_key is None:
            key = await self.store.lookup_rsa_key("kid1")
            if key is None:
                pass
                # todo: generate rsa key
            else:
                self.jwt_signing_key = JsonWebKey.import_key(key)

        vp_type = await self.store.lookup_vp_type(vpsid)
        ro_nonce = await self.store.lookup_vp_nonce(vpsid)

        client_metadata_uri = add_query_param_to_url(
            urllib.parse.urljoin(
                self.base_url, "/_matrix/client/v3/vp_client_metadata"
            ),
            "vpsid",
            vpsid,
        )

        payload = {
            "client_id": client_id,
            "response_uri": client_id,
            "nonce": ro_nonce,
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "presentation_definition": {
                "id": vpsid,
                "input_descriptors": make_input_descriptors(vp_type),
            },
            "client_metadata_uri": client_metadata_uri,
        }

        ro_jwt = jwt.encode({"alg": "RS256"}, payload, self.jwt_signing_key)

        return 200, ro_jwt


def register_servlets(hs, http_server):
    HandleVpRequest(hs).register(http_server)
