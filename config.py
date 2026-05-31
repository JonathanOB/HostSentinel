import yaml
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

_config = None


def get_config():
    global _config
    if _config is None:
        with open(DEFAULT_CONFIG_PATH, 'r') as f:
            _config = yaml.safe_load(f)
    return _config
