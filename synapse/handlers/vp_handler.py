import base64
import json
import logging
import urllib.parse
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse
from authlib.jose import JsonWebToken

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from jsonpath_ng import parse as jsonpath_parse
from jwcrypto.jwk import JWK
from sd_jwt.verifier import SDJWTVerifier

from synapse.api.constants import VPSessionStatus, VPType
from synapse.api.errors import SynapseError
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict, Requester

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


JSON_PATH: Dict[VPType, List[str]] = {
    VPType.AGE_OVER_13: ["$.is_older_than_13"],
    VPType.AFFILIATION: ["$.companyName"],
    VPType.JOIN_CONFERENCE: ["$.vc.credentialSubject.name"]
}

SUBMISSION_REQUIREMENTS: Dict[VPType, List[Dict[str, any]]] = {
    VPType.AGE_OVER_13: [
        {"name": "Age over 13 years old", "rule": "pick", "count": 1, "from": "A"}
    ],
    VPType.AFFILIATION: [
        {"name": "Affiliation", "rule": "pick", "count": 1, "from": "A"}
    ],
    VPType.JOIN_CONFERENCE: [
        {"name": "Conference Participation", "rule": "pick", "count": 1, "from": "A"}
    ]
}

SUBMISSION_VC_FORMAT_SD_JWT: Dict[str, Dict[str, List[str]]] = {
    "vc+sd-jwt": {
        "alg": ["ES256", "ES256K"],
    }
}

SUBMISSION_VC_FORMAT_JWT_VC_JSON: Dict[str, Dict[str, List[str]]] = {
    "jwt_vc_json": {
        "alg": ["ES256"]
    }
}

INPUT_DESCRIPTORS: Dict[VPType, List[Dict[str, any]]] = {
    VPType.AGE_OVER_13: [
        {
            "group": ["A"],
            "id": "identity_credential_based_on_myna",
            "name": "年齢が13以上であることを確認します",
            "purpose": "Matrix利用者に自身の年齢に関する情報を提示することができるようになります",
            "format": SUBMISSION_VC_FORMAT_SD_JWT,
            "constraints": {
                "fields": [
                    {
                        "path": JSON_PATH[VPType.AGE_OVER_13],
                        "filter": {
                            "type": "string",
                            # todo: to be implemented. may be JSON Schema URL?
                            "const": "",
                        },
                    }
                ],
                # This indicates that the Conformant Consumer MUST limit
                # submitted fields to those listed in the fields array
                "limit_disclosure": "required",
            },
        }
    ],
    VPType.AFFILIATION: [
        {
            "group": ["A"],
            "id": "affiliation",
            "name": "所属情報を確認します",
            "purpose": "Matrix利用者に自身の所属を提示することができるようになります",
            "format": SUBMISSION_VC_FORMAT_SD_JWT,
            "constraints": {
                "fields": [
                    {
                        "path": JSON_PATH[VPType.AFFILIATION],
                        "filter": {
                            "type": "string",
                            "const": "",  # todo: to be implemented
                        },
                    }
                ],
                "limit_disclosure": "required",
            },
        }
    ],
    VPType.JOIN_CONFERENCE: [
        {
            "group": ["A"],
            "id": "joinConference",
            "name": "カンファレンスへの参加を確認します",
            "purpose": "Matrix利用者にカンファレンスへの参加を提示することができるようになります",
            "format": SUBMISSION_VC_FORMAT_JWT_VC_JSON,
            "constraints": {
                "fields": [
                    {
                        "path": JSON_PATH[VPType.JOIN_CONFERENCE],
                        "filter": {
                            "type": "string",
                            "const": "",  # todo: to be implemented
                        },
                    }
                ],
                "limit_disclosure": "required",
            },
        }
    ]
}


def resolve_json_path(
    vp_type: VPType, verified_claims: Dict[str, any]
) -> Dict[str, List[any]]:
    result = []
    paths = JSON_PATH[vp_type]
    for path in paths:
        expr = jsonpath_parse(path)
        matches = expr.find(verified_claims)
        result.append([each.value for each in matches])
    return dict(zip(paths, result))


def make_required_descriptors(
    vp_type: VPType,
) -> Tuple[List[Dict[str, any]], List[Dict[str, any]]]:
    return INPUT_DESCRIPTORS[vp_type], SUBMISSION_REQUIREMENTS[vp_type]


def subject_info(dn) -> Tuple:
    org_names = dn.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    country_names = dn.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    state_names = dn.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)
    locality_names = dn.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)

    address = country_names + state_names + locality_names

    return org_names, address


def validity_period(cert) -> Tuple[str, str]:
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except Exception:
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

    return str(not_before), str(not_after)


def decode_base64url(s):
    return base64.urlsafe_b64decode(s + b"=" * ((4 - len(s) & 3) & 3))


def extract_issuer_info(all_claims: JsonDict, raw_vp_token: str) -> JsonDict:
    result = {
        "issuer_name": "UNKNOWN",
        "issuer_domain": "UNKNOWN",
        "issuer_address": "UNKNOWN",
        "issuer_authenticator_org_name": "UNKNOWN",
        "issuer_authenticator_address": "UNKNOWN",
        "not_before": "UNKNOWN",
        "not_after": "UNKNOWN",
    }

    iss_claim = all_claims.get("iss", None)
    if iss_claim is not None:
        try:
            result["issuer_domain"] = urlparse(iss_claim).netloc
        except Exception as ex:
            logger.warning("unable to get issuer domain from iss claim: %s" % ex)

    header_dict = None
    try:
        jwt_header = raw_vp_token.strip().split(".")[0]
        header_dict = json.loads(decode_base64url(jwt_header.encode("ascii")))
    except Exception as ex:
        logger.warning("unable to get issuer info from jwt header: %s" % ex)

    if header_dict is not None:
        try:
            chain = get_certificate_chain_from_header(header_dict)
            cert_data = chain[0].encode("ascii").strip()
            cert = x509.load_pem_x509_certificate(
                cert_data, default_backend()
            )

            issuer_org_names, issuer_address = subject_info(cert.subject)
            issuer_authenticator_org_names, issuer_authenticator_address = subject_info(
                cert.issuer
            )

            not_before, not_after = validity_period(cert)
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

            if len(issuer_org_names) > 0:
                result["issuer_name"] = issuer_org_names[0].value
            if len(issuer_address) > 0:
                result["issuer_address"] = " ".join([x.value for x in issuer_address])

            if len(issuer_authenticator_org_names) > 0:
                result[
                    "issuer_authenticator_org_name"
                ] = issuer_authenticator_org_names[0].value
            if len(issuer_authenticator_address) > 0:
                result["issuer_authenticator_address"] = " ".join(
                    [x.value for x in issuer_authenticator_address]
                )

            if len(sans.value) > 0:
                result["issuer_domain"] = " ".join(
                    sans.value.get_values_for_type(x509.DNSName)
                )
            result["not_before"] = not_before
            result["not_after"] = not_after
        except Exception as ex:
            logger.warning("unable to get issuer info from: %s" % ex)

    return result


def get_issuer_public_key_from_certificate(pem_cert: str) -> JWK:
    return JWK.from_pem(pem_cert.encode("utf8"))


def get_certificate_chain_from_header(header: dict) -> List[str]:
    x5c = header.get("x5c", None)
    x5u = header.get("x5u", None)
    chain = []

    if not (x5c is None or len(x5c) < 1):
        chain = [x509_certificate_prefix + "\n" +
                 each + "\n" +
                 x509_certificate_suffix
                 for each in x5c]
    elif x5u is not None:
        logger.warning("x5c is not present, but x5u is present: %s" % x5u)
        try:
            assert isinstance(x5u, str)
            response = requests.get(x5u, timeout=(2, 3))
            if response.status_code == 200:
                tmp = [each.strip() for each in
                       response.content.decode("ascii").split(x509_certificate_suffix)]
                for cert in tmp:
                    if cert != "":
                        chain.append(cert + "\n" + x509_certificate_suffix)
            else:
                logger.warning("http status code : %s" % response.status_code)
        except Exception as ex:
            logger.warning("Exception occurred: %s" % ex)
            logger.warning("Unable to retrieve certificate from x5u url: %s" % x5u)

    return chain

def get_issuer_public_key(iss: str, header: dict) -> JWK:

    chain = get_certificate_chain_from_header(header)

    if len(chain) == 0:
        raise Exception("Public key cannot be obtained from either x5c or x5u")

    # todo: verify certificate chain

    public_key = get_issuer_public_key_from_certificate(chain[0])

    # todo: Retrieve the key from `iss` and verify that it matches the one in x5c
    # public_from_iss = ...

    return public_key


x509_certificate_prefix = "-----BEGIN CERTIFICATE-----"
x509_certificate_suffix = "-----END CERTIFICATE-----"


class VerifiablePresentationHandler:
    def __init__(self, hs: "HomeServer"):
        self.base_url = hs.config.server.public_baseurl
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    def _verify_vp_token(
        self, format: str, vp_token: str, expected_aud: str, expected_nonce: str
    ) -> dict:
        try:
            if format == "vc+sd-jwt":
                verifier = SDJWTVerifier(
                    vp_token,
                    get_issuer_public_key,
                    expected_aud=expected_aud,
                    expected_nonce=expected_nonce,
                )
                return verifier.get_verified_payload()
            elif format == "jwt_vc_json":
                parts = vp_token.split(".")
                header = json.loads(decode_base64url(parts[0].strip().encode("ascii")))
                key = get_issuer_public_key("dummy", header)
                jwt = JsonWebToken(["RS256", "ES256K", "ES256"])
                claims = jwt.decode(vp_token, key=key.export_public(as_dict=True))
                return claims
            else:
                logger.warning("Unknown format: %s" % format)
                return {}
        except Exception as ex:
            logger.warning("Exception %s occurred while verifying vp_token" % ex)
            logger.warning("Unable to verify vp_token %s" % vp_token)
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Unable to verify vp_token")

    def _verify_descriptor_map(
        self, sid: str, vp_type: VPType, verification_target: List[dict]
    ) -> None:
        descriptor_choices, _ = make_required_descriptors(vp_type)

        logger.warning("!!! sid : %s" % sid)
        logger.warning("!!! verification target : %s" % verification_target)
        logger.warning("!!! descriptor_choices : %s" % descriptor_choices)

        for target in verification_target:
            try:
                dm_id = target["id"]
                dm_format = target["format"]
                _ = target["path"]
            except KeyError as e:
                logger.warning("Key %s not found in descriptor_map" % e.args[0])
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "Key %s not found in descriptor_map" % e.args[0],
                )
            check = False
            logger.warning("!!! dm_id: %s, dm_format: %s" % (dm_id, dm_format))
            for choice in descriptor_choices:
                logger.warning("!!! choice : %s" % choice)
                if choice["id"] == dm_id and dm_format in choice["format"]:
                    check = True
                    break
                else:
                    logger.warning("!!! choice[\"id\"] != dm_id or dm_format not in choice[\"format\"]")
                    logger.warning("!!! %s != %s or %s not in %s" % (choice["id"], dm_id, dm_format, choice["format"]))
            if not check:
                logger.warning("descriptor_map id or format is invalid")
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST, "descriptor_map id or format is invalid"
                )

    def _verify_presentation_submission(
        self, sid: str, vp_type: VPType, presentation_submission_dict: dict
    ) -> None:

        try:
            _ = presentation_submission_dict["id"]
            ps_definition_id = presentation_submission_dict["definition_id"]
            ps_descriptor_map = presentation_submission_dict["descriptor_map"]
        except KeyError as e:
            logger.warning("Key %s not found in presentation_submission" % e.args[0])
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Key %s not found in presentation_submission" % e.args[0],
            )

        if ps_definition_id != sid:
            logger.warning("definition_id must equal to %s" % sid)
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "definition_id must equal to %s" % sid
            )
        self._verify_descriptor_map(sid, vp_type, ps_descriptor_map)

    def _get_credential_format(self, presentation_submission_dict: dict):
        ps_descriptor_map = presentation_submission_dict["descriptor_map"]

        # todo: 要素が複数ある場合を考慮すべき
        dm_format = ps_descriptor_map[0]["format"]
        return dm_format

    async def handle_vp_response(self, request: SynapseRequest, sid: str):
        content_type_list = request.requestHeaders.getRawHeaders("Content-Type")

        # check content-type header
        if (
            len(content_type_list) != 1
            or content_type_list[0] != "application/x-www-form-urlencoded"
        ):
            logger.warning("content-type is not application/x-www-form-urlencoded")
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Error Unexpected Content-Type")

        # get vp_token and presentation_submission from request
        try:
            content = parse_qs(request.content.read().decode("utf-8"))
            vp_token = content.get("vp_token", None)
            presentation_submission = content.get("presentation_submission", None)
        except Exception:
            logger.warning("Error parsing request body")
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Error parsing request body")

        # check number of vp_token and presentation_submission
        if vp_token is None or len(vp_token) != 1:
            logger.warning("Only one vp_token is assumed to exist.")
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Only one vp_token is assumed to exist."
            )
        if presentation_submission is None or len(presentation_submission) != 1:
            logger.warning("Only one presentation_submission is assumed to exist.")
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Only one presentation_submission is assumed to exist.",
            )

        # verification
        expected_aud = urllib.parse.urljoin(
            self.base_url, "/".join(["/_matrix/client/v3/vp_response", sid])
        )
        ### WIP
        expected_aud = "https://ownd-project.com:8008/"

        expected_nonce = await self._store.lookup_vp_ro_nonce(sid)
        raw_token_value = vp_token[0]
        vp_type = await self._store.lookup_vp_type(sid)

        try:
            presentation_submission_dict = json.loads(presentation_submission[0])
        except Exception:
            logger.warning("Unable to parse presentation_submission")
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Unable to parse presentation_submission"
            )

        self._verify_presentation_submission(sid, vp_type, presentation_submission_dict)

        format = self._get_credential_format(presentation_submission_dict)
        verified_claims = self._verify_vp_token(
            format, raw_token_value, expected_aud, expected_nonce
        )

        return raw_token_value, verified_claims

    async def register_claims(
        self,
        sid: str,
        raw_token_value: str,
        verified_claims: dict,
    ) -> None:

        user_id = await self._store.lookup_vp_userid(sid)

        if user_id is None or user_id == "":
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Unknown user_id")

        vp_type = await self._store.lookup_vp_type(sid)

        main_claims = resolve_json_path(vp_type, verified_claims)

        await self._store.register_vp_data(
            user_id, vp_type, main_claims, verified_claims, raw_token_value
        )
        await self._store.update_vp_session_status(sid, VPSessionStatus.POSTED)
