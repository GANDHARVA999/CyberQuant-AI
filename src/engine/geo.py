"""Approximate, OFFLINE region of an IPv4 address from its /8 registry block (RIR allocation).
This is NOT precise geolocation: it only says which regional internet registry the address block was allocated to,
and is drawn at that region's centre with a small deterministic spread. Replace with a GeoIP database for city/country accuracy."""
from __future__ import annotations
import zlib

_R = {"APNIC": (28.0, 100.0, "Asia-Pacific"), "RIPE": (52.0, 20.0, "Europe / Middle East"), "ARIN": (39.0, -98.0, "North America"),
      "LACNIC": (-14.0, -60.0, "Latin America"), "AFRINIC": (2.0, 22.0, "Africa")}
_BLOCKS = {
    "APNIC": [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
              125, 126, 133, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223],
    "RIPE": [2, 5, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188,
             193, 194, 195, 212, 213, 217],
    "LACNIC": [177, 179, 181, 186, 187, 189, 190, 200, 201],
    "AFRINIC": [41, 102, 105, 196, 197],
}
_MAP = {b: r for r, bs in _BLOCKS.items() for b in bs}


def region_of(ip: str | None) -> dict:
    try: first = int(str(ip).split(".")[0])
    except (ValueError, AttributeError): first = -1
    key = _MAP.get(first, "ARIN")
    lat, lon, name = _R[key]
    h = zlib.crc32(str(ip).encode())
    return {"registry": key, "region": name, "lat": lat + ((h & 0xFF) / 255 - .5) * 26, "lon": lon + (((h >> 8) & 0xFF) / 255 - .5) * 46}
