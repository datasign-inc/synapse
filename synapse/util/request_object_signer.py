import logging
from typing import TYPE_CHECKING, Optional

from authlib.jose import JsonWebKey, Key as JwkKey, jwt

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class OID4VCRequestObjectSigner:
    def __init__(self, hs: "HomeServer"):
        self._hs = hs
        self._store = hs.get_datastores().main
        self.__signing_key: Optional[JwkKey] = None

    async def _register_signing_key(self, kid: str, key: JwkKey) -> None:
        await self._store.register_ro_signing_key(kid, key.as_json(is_private=True))

    async def setup_signing_key(self, kid: str) -> None:
        if self.__signing_key is not None:
            return

        signing_key = await self._store.lookup_ro_signing_key(kid)
        if signing_key is None:
            signing_key = self._generate_default_signing_key(kid)
            await self._register_signing_key(kid, signing_key)

        self._kid = kid
        self.__signing_key = signing_key

    def sign(self, header: dict, payload: dict) -> str:
        if self.__signing_key is None:
            raise RuntimeError("No signing key setup")
        return jwt.encode(
            {"kid": self._kid, "alg": self.decide_alg(), **header},
            payload,
            self.__signing_key,
        )

    def as_dict(self) -> dict:
        if self.__signing_key is None:
            raise RuntimeError("No signing key setup")
        return self.__signing_key.as_dict()

    def decide_alg(self) -> str:
        if self.__signing_key is None:
            raise RuntimeError("No signing key setup")
        jwk = self.__signing_key.as_dict()
        kty = jwk["kty"]

        if kty == "RSA":
            return "RS256"

        if kty == "EC":
            crv = jwk["crv"]
            if crv == "P-256":
                return "ES256"

        if kty == "OKP":
            crv = jwk["crv"]
            if crv == "Ed25519":
                return "EdDSA"

        raise RuntimeError("Unable to decide alg for key")

    @staticmethod
    def _generate_default_signing_key(kid: str) -> JwkKey:
        key = JsonWebKey.generate_key(
            "EC", "P-256", is_private=True, options={"kid": kid}
        )
        return key
