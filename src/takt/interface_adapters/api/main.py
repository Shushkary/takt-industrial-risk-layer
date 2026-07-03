from __future__ import annotations

import sys

from . import app as _app

sys.modules[__name__] = _app
