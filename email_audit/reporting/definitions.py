"""Load packaged reporting definitions."""

from functools import lru_cache
from importlib.resources import files

import yaml


@lru_cache(maxsize=None)
def load_definitions(name):
    """Load a reporting catalogue, failing explicitly if it is invalid."""
    path = files("email_audit").joinpath("data").joinpath(name + ".yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"Unable to load reporting definitions {name!r}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Reporting definitions {name!r} must contain a mapping")
    return data
