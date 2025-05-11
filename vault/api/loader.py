import importlib
from typing import Tuple

from fastapi import APIRouter
from vault.api.routes import functions_map


def parse_version(v: str) -> Tuple[int, ...]:
    # "v1.2" -> (1, 2)
    parts = v.lstrip("v").split('.')
    return tuple(int(p) for p in parts)


def build_router_for_version(version: str) -> APIRouter:
    # Гарантируем, что routes.py загружен
    importlib.import_module("vault.api.routes")

    router = APIRouter()
    # все уникальные пути из functions_map
    all_paths = set(p for routes in functions_map.values() for p in routes)

    for path in sorted(all_paths):
        # найти версии <= текущей, в которых path зарегистрирован
        candidates = [v for v, routes in functions_map.items()
                      if path in routes and parse_version(v) <= parse_version(version)]
        if not candidates:
            continue
        # выбрать самую новую из подходящих
        chosen = max(candidates, key=parse_version)
        func, methods = functions_map[chosen][path]
        router.add_api_route(path, func, methods=methods)

    return router