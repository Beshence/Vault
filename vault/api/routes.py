from typing import Callable, Dict, List, Tuple

# Словарь: версия -> (path -> (func, methods))
functions_map: Dict[str, Dict[str, Tuple[Callable, List[str]]]] = {}


def register(version: str, path: str, methods: List[str] = ["GET"]):
    """
    Декоратор для регистрации функции-обработчика на конкретную версию и путь
    """
    def decorator(func: Callable):
        functions_map.setdefault(version, {})[path] = (func, methods)
        return func
    return decorator


@register("v1.0", "/get_user")
def get_user_v1_0():
    return {"user": "from v1.0"}


@register("v1.2", "/get_user")
def get_user_v1_2():
    return {"user": "from v1.2"}