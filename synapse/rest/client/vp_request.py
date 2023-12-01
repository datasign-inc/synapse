import logging
import urllib.parse
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict
from synapse.util.stringutils import add_query_param_to_url

logger = logging.getLogger(__name__)


def make_required_descriptors(vp_type: str):
    if vp_type == "ageOver13":
        descriptors = [
            {
                "group": "A",
                "id": "identity_credential_based_on_myna",
                "name": "年齢が13以上であることを確認します",
                "purpose": "Matrixの機能を全て利用するためには、年齢の確認が必要です",
                "format": {
                    "vc+sd-jwt": {
                        "alg": ["ES256", "ES256K"],
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            # https://github.com/datasign-inc/tw2023-demo-vci/blob/e90e743a4d3ed5ff559c42a9aa4e0b1904939eea/proxy-vci/src/vci/identityCredential.ts#L187
                            "path": ["$.is_older_than_13"],
                            "filter": {
                                "type": "string",
                                # todo: to be implemented. may be JSON Schema URL?
                                "const": "",
                            },
                        }
                    ],
                    # This indicates that the Conformant Consumer MUST limit
                    # submitted fields to those listed in the fields array
                    "limit_disclosure,": "required",
                },
            }
        ]

        # submission_requirements property defines which
        # Input Descriptors are required for submission,
        requirements = [
            {"name": "Age over 13 years old", "rule": "pick", "count": 1, "from": "A"}
        ]

        return descriptors, requirements

    if vp_type == "affiliation":
        descriptors = [
            {
                "group": "A",
                "id": "affiliation",
                "name": "所属情報を確認します",
                "purpose": "Matrix利用者に自身の所属を提示することができるようになります",
                "format": {
                    "vc+sd-jwt": {
                        "alg": ["ES256", "ES256K"],
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            # https://github.com/datasign-inc/tw2023-demo-vci/blob/e90e743a4d3ed5ff559c42a9aa4e0b1904939eea/employee-vci/src/vci/employeeCredential.ts#L50
                            "path": ["$.division"],
                            "filter": {
                                "type": "string",
                                "const": "",  # todo: to be implemented
                            },
                        }
                    ],
                    "limit_disclosure,": "required",
                },
            }
        ]

        requirements = [
            {"name": "Affiliation", "rule": "pick", "count": 1, "from": "A"}
        ]

        return descriptors, requirements

    raise ValueError("unexpected vp_type %s" % vp_type)


class HandleVpRequest(RestServlet):
    PATTERNS = client_patterns("/vp_request$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main
        self._ro_signer = hs.get_oid4vc_request_object_signer()
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

        await self._ro_signer.setup_signing_key("kid1")

        vp_type = await self.store.lookup_vp_type(vpsid)
        ro_nonce = await self.store.lookup_vp_nonce(vpsid)

        client_metadata_uri = add_query_param_to_url(
            urllib.parse.urljoin(
                self.base_url, "/_matrix/client/v3/vp_client_metadata"
            ),
            "vpsid",
            vpsid,
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
                "id": vpsid,
                "input_descriptors": input_descriptors,
                "submission_requirements": requirements,
            },
            "client_metadata_uri": client_metadata_uri,
        }

        ro_jwt = self._ro_signer({}, payload)
        return 200, ro_jwt


def register_servlets(hs, http_server):
    HandleVpRequest(hs).register(http_server)
