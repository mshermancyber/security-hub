"""Runtime config — env-driven with sensible defaults."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

DB_PATH = Path(os.environ.get("SECHUB_DB", PROJECT_DIR / "data" / "sechub.sqlite"))
TAXONOMY_DIR = BASE_DIR / "taxonomy"

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BASE = "https://api.first.org/data/v1/epss"

# Refresh cadences (seconds)
REFRESH_NEWS = int(os.environ.get("SECHUB_REFRESH_NEWS", 900))      # 15 min
REFRESH_KEV = int(os.environ.get("SECHUB_REFRESH_KEV", 3600))       # 1 hour
REFRESH_NVD = int(os.environ.get("SECHUB_REFRESH_NVD", 1800))       # 30 min

# NVD: pull recent window (days) on each refresh
NVD_LOOKBACK_DAYS = int(os.environ.get("SECHUB_NVD_LOOKBACK", 7))

# HTTP
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0"
HTTP_TIMEOUT = 20.0

# Optional API keys
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # increases NVD rate limits if set
