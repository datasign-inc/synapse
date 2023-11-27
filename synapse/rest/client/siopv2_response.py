import logging
from synapse.http.servlet import RestServlet
from synapse.types import JsonDict
from synapse.http.server import HttpServer
from synapse.http.site import SynapseRequest
from typing import Tuple
from synapse.rest.client._base import client_patterns
from urllib.parse import parse_qs
from synapse.http import redact_uri
from synapse.api.errors import Codes
from http import HTTPStatus
from synapse.handlers.oidc import Token


import inspect

logger = logging.getLogger(__name__)


class MyCustomEndpoint(RestServlet):
    PATTERNS = client_patterns("/siopv2_response$")  # 新しいエンドポイントのパスを指定

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self._siopv2_handler = hs.get_siopv2_handler()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:

        # 応答データを作成
        response_data = {
            "message": "Success!!",
        }

        return 200, response_data  # 応答を返す

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:

        siopv2_sid = request.args.get(b'sv2sid', [b''])[0].decode('utf-8')

        if siopv2_sid == '' or not await self.store.validate_siopv2_session(siopv2_sid, "created"):
            return 400, {"message": "Bad Request"}

        await self._siopv2_handler.handle_siopv2_response(request, siopv2_sid)

        response_data = {
            "message": "New endpoint data received.",
            "data": ""
        }

        return 200, response_data


def register_servlets(hs, http_server):
    MyCustomEndpoint(hs).register(http_server)