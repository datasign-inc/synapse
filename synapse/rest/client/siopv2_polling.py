import logging
from typing import Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class HandleSIOPv2Polling(RestServlet):
    PATTERNS = client_patterns("/siopv2_polling$")

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        siopv2_sid = request.args.get(b"sv2sid", [b""])[0].decode("utf-8")

        if siopv2_sid == "" or not await self.store.validate_siopv2_session(
            siopv2_sid, "posted"
        ):
            return 400, {"message": "Bad Request"}

        value = await self.store.get_login_token_for_siopv2_sid(siopv2_sid)
        await self.store.invalidate_siopv2_session(siopv2_sid)

        response_data = {"siopv2_sid": siopv2_sid, "login_token": value}

        return 200, response_data


def register_servlets(hs, http_server):
    HandleSIOPv2Polling(hs).register(http_server)
