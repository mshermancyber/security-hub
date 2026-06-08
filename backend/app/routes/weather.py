"""Lightweight weather + timezone proxy for the header clock widget.

Frontend sends the browser's IANA timezone (e.g. "America/New_York").
We derive a city name, geocode it, fetch current weather from Open-Meteo
(free, no API key), and return a compact payload.  Results are cached
in-process for 30 minutes to avoid hammering the upstream.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import timezone
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Query

from ..config import USER_AGENT

router = APIRouter(prefix="/api/weather", tags=["weather"])
log = logging.getLogger("sechub.weather")

_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 1800  # 30 minutes

_IANA_TZ_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-]{0,30}(/[A-Za-z][A-Za-z0-9_+\-]{0,30}){0,2}$")


def _city_from_tz(tz: str) -> str:
    """Extract a human-readable city name from an IANA timezone string."""
    parts = tz.rsplit("/", 1)
    city = parts[-1] if len(parts) > 1 else tz
    return city.replace("_", " ")


@router.get("")
async def get_weather(tz: str = Query("UTC", description="IANA timezone, e.g. America/New_York")):
    if not _IANA_TZ_RE.match(tz):
        raise HTTPException(400, "invalid timezone")

    now = time.monotonic()
    if tz in _cache and (now - _cache[tz][0]) < _CACHE_TTL:
        return _cache[tz][1]

    city = _city_from_tz(tz)
    result = {"city": city, "tz": tz, "temp_f": None, "condition": None, "icon": None}

    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=10, headers={"User-Agent": USER_AGENT},
                                      follow_redirects=True, max_redirects=3) as cx:
            geo = await safe_get(
                cx,
                f"https://geocoding-api.open-meteo.com/v1/search?name={quote(city)}&count=1",
                max_bytes=64 * 1024,
            )
            geo_data = geo.json()
            if not geo_data.get("results"):
                _cache[tz] = (now, result)
                return result

            loc = geo_data["results"][0]
            lat, lon = loc["latitude"], loc["longitude"]
            if loc.get("name"):
                result["city"] = loc["name"]

            wx = await safe_get(
                cx,
                f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
                f"&current=temperature_2m,weather_code&temperature_unit=fahrenheit&timezone={quote(tz)}",
                max_bytes=64 * 1024,
            )
            wx_data = wx.json()
            cur = wx_data.get("current", {})
            result["temp_f"] = cur.get("temperature_2m")
            result["condition"] = _WMO_CODE.get(cur.get("weather_code"), "")
            result["icon"] = _WMO_ICON.get(cur.get("weather_code"), "")
    except Exception:
        log.debug("weather fetch failed for tz=%s", tz, exc_info=True)

    _cache[tz] = (now, result)
    return result


_WMO_CODE: dict[int, str] = {
    0: "Clear", 1: "Mostly Clear", 2: "Partly Cloudy", 3: "Overcast",
    45: "Fog", 48: "Rime Fog",
    51: "Light Drizzle", 53: "Drizzle", 55: "Heavy Drizzle",
    61: "Light Rain", 63: "Rain", 65: "Heavy Rain",
    71: "Light Snow", 73: "Snow", 75: "Heavy Snow", 77: "Snow Grains",
    80: "Light Showers", 81: "Showers", 82: "Heavy Showers",
    85: "Light Snow Showers", 86: "Snow Showers",
    95: "Thunderstorm", 96: "Thunderstorm + Hail", 99: "Severe Thunderstorm",
}

_WMO_ICON: dict[int, str] = {
    0: "☀", 1: "⛅", 2: "⛅", 3: "☁",
    45: "🌫", 48: "🌫",
    51: "🌦", 53: "🌧", 55: "🌧",
    61: "🌦", 63: "🌧", 65: "🌧",
    71: "❄", 73: "🌨", 75: "🌨", 77: "❄",
    80: "🌦", 81: "🌧", 82: "🌧",
    85: "🌨", 86: "🌨",
    95: "⚡", 96: "⚡", 99: "⚡",
}
