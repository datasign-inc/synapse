import logging
import urllib.parse
from http import HTTPStatus
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from jwcrypto.jwk import JWK
from sd_jwt.verifier import SDJWTVerifier

from synapse.api.constants import VPSessionStatus
from synapse.api.errors import SynapseError
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


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
            content_bytes = request.content.read()
            content = parse_qs(content_bytes.decode("utf-8"))
            vp_token = content.get("vp_token", None)
            presentation_submission = content.get("presentation_submission", None)

            if vp_token is None or len(vp_token) != 1:
                raise Exception("vp_token not found")
            if presentation_submission is None or len(presentation_submission) != 1:
                raise Exception("presentation_submission not found")
        except Exception:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Unable to parse x-www-form-urlencoded data",
            )

        # verify vp_token
        try:
            expected_aud = urllib.parse.urljoin(
                self.base_url, "/".join(["/_matrix/client/v3/vp_response", sid])
            )
            expected_nonce = await self._store.lookup_vp_ro_nonce(sid)
            raw_token_value = vp_token[0]
            verifier = SDJWTVerifier(
                raw_token_value,
                self.get_issuer_public_key,
                expected_aud=expected_aud,
                expected_nonce=expected_nonce,
            )
            claims = verifier.get_verified_payload()
            return raw_token_value, claims
        except Exception:
            logger.info("Unable to verify vp_token")
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Unable to verify vp_token")

    async def register_claims(
        self,
        request: SynapseRequest,
        sid: str,
        raw_token_value: str,
        verified_claims: dict,
    ) -> None:
        requester = await self._auth.get_user_by_req(request)

        user_id = requester.requester.to_string()
        vp_type = await self._store.lookup_vp_type(sid)

        await self._store.register_vp_data(
            user_id, vp_type, verified_claims, raw_token_value
        )
        await self._store.update_vp_session_status(sid, VPSessionStatus.POSTED)
