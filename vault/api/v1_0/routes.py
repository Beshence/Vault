from typing import Annotated

from fastapi import APIRouter, HTTPException
from fastapi.params import Query

from vault.api import versions

router = APIRouter()

@router.get(
    "/ping",
    name="Ping",
    description="Ping server and get information about it.")
def ping(error: Annotated[bool, Query()] = False) -> dict:
    if error:
        raise HTTPException(400, detail="You sent bad request on purpose.")

    return {
        "ping": "Pong!",
        "latest_api_version": versions[-1]
    }