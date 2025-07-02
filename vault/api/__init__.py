import importlib

from fastapi import APIRouter

from vault.misc import parse_version

# {version: {endpoint: (func, kwargs)}}
functions_map: dict[str, dict[str, tuple[callable, dict]]] = {}


def versioned_route(version: str, endpoint: str, **kwargs):
    def decorator(func: callable):
        functions_map.setdefault(version, {})[endpoint] = (func, kwargs)
        return func
    return decorator


def build_router_for_version(version: str) -> APIRouter:
    importlib.import_module("vault.api.routes")
    #importlib.import_module("vault.api.vault.routes")
    importlib.import_module("vault.api.chain.routes")

    router = APIRouter()
    all_paths = set(p for routes in functions_map.values() for p in routes)

    for endpoint in sorted(all_paths):
        # versions with this endpoint <= current version
        candidates = [v for v in functions_map if endpoint in functions_map[v] and parse_version(v) <= parse_version(version)]
        if not candidates:
            continue
        chosen = max(candidates, key=parse_version)
        func, kwargs = functions_map[chosen][endpoint]
        router.add_api_route(endpoint, func, **kwargs)

    return router