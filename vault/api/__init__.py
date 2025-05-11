import importlib

from fastapi import APIRouter

from vault.misc import parse_version

# version -> (path -> (func, kwargs))
functions_map: dict[str, dict[str, tuple[callable, dict]]] = {}


def versioned_route(version: str, path: str, **kwargs):
    def decorator(func: callable):
        functions_map.setdefault(version, {})[path] = (func, kwargs)
        return func
    return decorator


def build_router_for_version(version: str) -> APIRouter:
    importlib.import_module("vault.api.routes")

    router = APIRouter()
    all_paths = set(p for routes in functions_map.values() for p in routes)

    for path in sorted(all_paths):
        # versions with this path <= current
        candidates = [v for v in functions_map if path in functions_map[v] and parse_version(v) <= parse_version(version)]
        if not candidates:
            continue
        chosen = max(candidates, key=parse_version)
        func, kwargs = functions_map[chosen][path]
        router.add_api_route(path, func, **kwargs)

    return router