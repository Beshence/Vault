from typing import Annotated

from fastapi import Query, HTTPException

from vault.api import versioned_route
from vault.misc import get_versions

@versioned_route(
    version="v1.0",
    path="/ping",
    methods=["GET"],
    name="Ping",
    description="Ping server and get information about it.")
def ping(error: Annotated[bool, Query()] = False) -> dict:
    if error:
        raise HTTPException(400, detail="You sent bad request on purpose.")

    return {
        "ping": "Pong!",
        "latest_api_version": get_versions()[-1]
    }