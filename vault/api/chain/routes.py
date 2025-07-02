from typing import Annotated

from fastapi import Path, Body, HTTPException

from vault.api import versioned_route
from vault.misc import check_chain_name


@versioned_route(
    version="v1.0",
    endpoint="/chain/{chain_name}",
    methods=["POST"],
    name="Initialize new chain",
    description="Creates new chain with specified name.",
    tags=["chain"])
def new_chain(chain_name: Annotated[str, Path()], settings: Annotated[dict, Body()]) -> dict:
    if not check_chain_name(chain_name):
        raise HTTPException(status_code=400, detail="Invalid chain name")

    return {
        "okay": chain_name
    }