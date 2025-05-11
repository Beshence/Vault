import importlib

from fastapi import APIRouter

versions = ["v1.0"]

def load_router(version: str) -> APIRouter:
    module_path = f"vault.api.{version.replace(".", "_")}.routes"
    module = importlib.import_module(module_path)
    return getattr(module, "router")

def get_versions_map() -> dict[str, APIRouter]:
    versions_map = {v: load_router(v) for v in versions}
    versions_map["latest"] = load_router(versions[-1])
    return versions_map
