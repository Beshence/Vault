import json


def parse_version(v: str) -> tuple[int, ...]:
    parts = v.lstrip("v").split('.')
    return tuple(int(p) for p in parts)

def get_versions():
    return json.loads(open("vault/api/versions.json").read())