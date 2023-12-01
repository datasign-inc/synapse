from typing import TYPE_CHECKING

from synapse.http.server import HttpServer

if TYPE_CHECKING:
    from synapse.server import HomeServer


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    pass
