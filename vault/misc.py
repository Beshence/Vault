import json


def parse_version(v: str) -> tuple[int, ...]:
    if v == "latest":
        return parse_version(get_versions()[-1])
    parts = v.lstrip("v").split('.')
    return tuple(int(p) for p in parts)

def get_versions(with_latest: bool = False):
    return json.loads(open("vault/api/versions.json").read()) + (["latest"] if with_latest else [])

def check_chain_name(chain_name: str) -> bool:
    if not chain_name.islower(): return False
    if len(chain_name) > 32: return False
    if not chain_name.isalpha(): return False
    return True