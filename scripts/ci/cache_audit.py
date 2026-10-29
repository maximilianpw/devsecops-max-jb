"""Alias de compatibilité pour l'audit du cache registre."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_registry_cache import *  # noqa: E402,F401,F403
