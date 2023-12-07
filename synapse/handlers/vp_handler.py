import json
import logging
import urllib.parse
from http import HTTPStatus
from typing import TYPE_CHECKING, List
from urllib.parse import parse_qs

from jwcrypto.jwk import JWK
from sd_jwt.verifier import SDJWTVerifier

from synapse.api.constants import VPSessionStatus, VPType
from synapse.api.errors import SynapseError
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def make_required_descriptors(vp_type: VPType):
    if vp_type == VPType.AGE_OVER_13:
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

    if vp_type == VPType.AFFILIATION:
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


class VerifiablePresentationHandler:
    def __init__(self, hs: "HomeServer"):
        self.base_url = hs.config.server.public_baseurl
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    def _get_issuer_public_key_from_certificate(self, pem_cert: str) -> JWK:
        return JWK.from_pem(pem_cert.encode("utf8"))

    def get_issuer_public_key(self, iss: str, header: dict) -> JWK:
        x5c = header.get("x5c", None)

        if x5c is None or len(x5c) < 1:
            raise Exception("x5c not found in JWT header")

        pubkey_from_x5c = self._get_issuer_public_key_from_certificate(x5c[0])

        # todo: Retrieve the key from `iss` and verify that it matches the one in x5c
        # pubkey_from_iss = ...

        return pubkey_from_x5c

    def _verify_vp_token(
        self, vp_token: str, expected_aud: str, expected_nonce: str
    ) -> dict:
        try:
            verifier = SDJWTVerifier(
                vp_token,
                self.get_issuer_public_key,
                expected_aud=expected_aud,
                expected_nonce=expected_nonce,
            )
            return verifier.get_verified_payload()
        except Exception:
            logger.info("Unable to verify vp_token %s" % vp_token)
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Unable to verify vp_token")

    def _verify_descriptor_map(
        self, sid: str, vp_type: VPType, verification_target: List[dict]
    ) -> None:
        descriptor_choices, _ = make_required_descriptors(vp_type)
        for target in verification_target:
            try:
                dm_id = target["id"]
                dm_format = target["format"]
                dm_path = target["path"]
            except KeyError as e:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "Key %s not found in descriptor_map" % e.args[0],
                )
            check = False
            for choice in descriptor_choices:
                if choice["id"] == dm_id and dm_format in choice["format"]:
                    check = True
                    break
            if not check:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST, "descriptor_map id or format is invalid"
                )

    def _verify_presentation_submission(
        self, sid: str, vp_type: VPType, presentation_submission: str
    ) -> None:
        try:
            presentation_submission_dict = json.loads(presentation_submission)
        except Exception:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Unable to parse presentation_submission"
            )

        try:
            presentation_submission_dict["id"]
            ps_definition_id = presentation_submission_dict["definition_id"]
            ps_descriptor_map = presentation_submission_dict["descriptor_map"]
        except KeyError as e:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Key %s not found in presentation_submission" % e.args[0],
            )

        if ps_definition_id != sid:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "definition_id must equal to %s" % sid
            )
        self._verify_descriptor_map(sid, vp_type, ps_descriptor_map)

    async def handle_vp_response(self, request: SynapseRequest, sid: str):
        content_type_list = request.requestHeaders.getRawHeaders("Content-Type")

        # check content-type header
        if (
            len(content_type_list) != 1
            or content_type_list[0] != "application/x-www-form-urlencoded"
        ):
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Error Unexpected Content-Type")

        # get vp_token and presentation_submission from request
        try:
            content = parse_qs(request.content.read().decode("utf-8"))
            vp_token = content.get("vp_token", None)
            presentation_submission = content.get("presentation_submission", None)
        except Exception:
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Error parsing request body")

        # check number of vp_token and presentation_submission
        if vp_token is None or len(vp_token) != 1:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Only one vp_token is assumed to exist."
            )
        if presentation_submission is None or len(presentation_submission) != 1:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Only one presentation_submission is assumed to exist.",
            )

        # verification
        expected_aud = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_response", sid])
        )
        expected_nonce = await self._store.lookup_vp_ro_nonce(sid)
        raw_token_value = vp_token[0]
        vp_type = await self._store.lookup_vp_type(sid)

        self._verify_presentation_submission(sid, vp_type, presentation_submission[0])
        verified_claims = self._verify_vp_token(
            raw_token_value, expected_aud, expected_nonce
        )

        return raw_token_value, verified_claims

    async def register_claims(
        self,
        request: SynapseRequest,
        sid: str,
        raw_token_value: str,
        verified_claims: dict,
    ) -> None:
        requester = await self._auth.get_user_by_req(request)

        user_id = requester.user.to_string()
        vp_type = await self._store.lookup_vp_type(sid)

        await self._store.register_vp_data(
            user_id, vp_type, verified_claims, raw_token_value
        )
        await self._store.update_vp_session_status(sid, VPSessionStatus.POSTED)
