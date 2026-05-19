"""
Classplus Golden_Eagle replacement API.

Endpoints (all GET, query-string compatible with the old Vercel API):

  GET /Golden_Eagle?url=<encoded>&token=<cp_token>&orgCode=<optional>

Behavior:
  - Non-DRM (.m3u8, /lc/, signed-url path) -> {"url": "<signed>"}
  - DRM (.mpd / /drm/ / /cc/ / _encn) -> {"MPD": "<mpd>", "KEYS": ["kid:key", ...]}
  - Error -> {"success": false, "error": "..."} (HTTP 200 with JSON so bot can detect)

Health:
  GET /                 -> {"ok": true}
  GET /health           -> {"ok": true}
"""

from __future__ import annotations

import base64
import os
import re
import sys
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

# ------------------------------------------------------------------ logging --
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("golden-eagle")

# --------------------------------------------------------------------- CDM --
CDM_DIR = Path(__file__).parent / "cdm"


def _load_device() -> Optional[Device]:
    """Load a pywidevine Device from /api/cdm/.

    Supports either:
      - A single .wvd file (preferred)
      - The legacy pair: device_client_id_blob  +  device_private_key.txt
    """
    if not CDM_DIR.exists():
        return None

    for wvd in CDM_DIR.glob("*.wvd"):
        try:
            log.info("Loading WVD device: %s", wvd.name)
            return Device.load(wvd)
        except Exception as e:
            log.warning("Failed to load %s: %s", wvd.name, e)

    blob = CDM_DIR / "device_client_id_blob"
    pkey = CDM_DIR / "device_private_key.txt"
    if blob.exists() and pkey.exists():
        try:
            pkey_bytes = pkey.read_bytes()
            blob_bytes = blob.read_bytes()
            dev = Device(
                type_=Device.Types.ANDROID,
                security_level=3,
                flags=None,
                private_key=pkey_bytes,
                client_id=blob_bytes,
            )
            log.info("Loaded legacy blob+pkey device")
            return dev
        except Exception as e:
            log.error("Failed to load legacy device files: %s", e)

    log.error("No usable Widevine device found in %s", CDM_DIR)
    return None


DEVICE: Optional[Device] = _load_device()

# ------------------------------------------------------------------ headers --
CP_HEADERS_BASE = {
    "accept-language": "en",
    "api-version": "56",
    "app-version": "1.12.1.1",
    "build-number": "56",
    "connection": "Keep-Alive",
    "content-type": "application/json",
    "device-details": "motorola_Moto G4_SDK-32",
    "device-id": "c28d3cb16bbdac01",
    "region": "IN",
    "user-agent": "Mobile-Android",
    "x-chrome-version": "143.0.7499.52",
    "isReviewerOn": "0",
    "is-apk": "0",
    "accept-encoding": "gzip",
}

CP_SIGNED_ENDPOINTS = [
    "https://api.classplusapp.com/cams/uploader/video/jw-signed-url",
]

# --------------------------------------------------------------------- app --
app = FastAPI(title="Classplus Golden_Eagle (self-hosted)")


@app.get("/")
@app.get("/health")
async def health():
    return {
        "ok": True,
        "cdm_loaded": DEVICE is not None,
        "service": "cp-golden-eagle",
    }


# --------------------------------------------------------------- helpers ----
def _is_drm_url(u: str) -> bool:
    lu = u.lower()
    return (
        lu.endswith(".mpd")
        or "/drm/" in lu
        or "/cc/" in lu
        or "_encn" in lu
    )


def _normalize_url(u: str) -> str:
    return u.replace(
        "https://cpvod.testbook.com/",
        "https://media-cdn.classplusapp.com/drm/",
    )


def _extract_org_code_from_url(u: str) -> Optional[str]:
    """Extract orgId from CDN paths like .../438039/lc/... or .../438039/cc/..."""
    m = re.search(r'/(\d{4,7})/(?:lc|cc|drm)/', u)
    return m.group(1) if m else None


async def _classplus_sign(client: httpx.AsyncClient, url: str, token: str, org_code: Optional[str] = None) -> dict:
    """Call the remaining live Classplus signer endpoint with Android-app headers."""
    headers = CP_HEADERS_BASE.copy()
    headers["x-access-token"] = token
    if org_code:
        headers["orgCode"] = org_code
        headers["org-code"] = org_code
    last_err: Any = None
    for ep in CP_SIGNED_ENDPOINTS:
        try:
            r = await client.get(ep, params={"url": url}, headers=headers, timeout=20)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and (
                    data.get("url")
                    or data.get("drmUrls")
                    or (data.get("data") or {}).get("url")
                    or (data.get("data") or {}).get("drmUrls")
                ):
                    return data
                last_err = f"empty response: {str(data)[:200]}"
            else:
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            last_err = str(e)
    raise RuntimeError(f"Classplus signing failed via jw-signed-url: {last_err}")


def _extract_signed_pieces(sign_data: dict) -> tuple[Optional[str], Optional[dict]]:
    """Return (plain_url, drm_urls_dict)."""
    plain = sign_data.get("url") or (sign_data.get("data") or {}).get("url")
    drm = sign_data.get("drmUrls") or (sign_data.get("data") or {}).get("drmUrls")
    return plain, drm


_PSSH_RE = re.compile(
    rb"<cenc:pssh[^>]*>([A-Za-z0-9+/=\s]+)</cenc:pssh>", re.IGNORECASE
)


def _extract_pssh_from_mpd(mpd_text: bytes) -> Optional[str]:
    m = _PSSH_RE.search(mpd_text)
    if not m:
        return None
    return re.sub(rb"\s+", b"", m.group(1)).decode("ascii")


async def _widevine_keys(
    client: httpx.AsyncClient,
    mpd_url: str,
    license_url: str,
    extra_headers: Optional[dict] = None,
) -> list[str]:
    if DEVICE is None:
        raise RuntimeError("CDM device not loaded on server")

    mpd_resp = await client.get(mpd_url, timeout=20)
    mpd_resp.raise_for_status()
    pssh_b64 = _extract_pssh_from_mpd(mpd_resp.content)
    if not pssh_b64:
        raise RuntimeError("PSSH not found in MPD")

    pssh = PSSH(pssh_b64)
    cdm = Cdm.from_device(DEVICE)
    session_id = cdm.open()
    try:
        challenge = cdm.get_license_challenge(session_id, pssh)
        lic_headers = {"Content-Type": "application/octet-stream"}
        if extra_headers:
            lic_headers.update(extra_headers)
        lic_resp = await client.post(
            license_url, content=challenge, headers=lic_headers, timeout=20
        )
        lic_resp.raise_for_status()
        cdm.parse_license(session_id, lic_resp.content)
        keys = []
        for k in cdm.get_keys(session_id):
            if k.type == "CONTENT":
                keys.append(f"{k.kid.hex}:{k.key.hex()}")
        if not keys:
            raise RuntimeError("No CONTENT keys returned by license server")
        return keys
    finally:
        cdm.close(session_id)


# ----------------------------------------------------------------- routes ---
@app.get("/Golden_Eagle")
async def golden_eagle(
    url: str = Query(..., description="Classplus media URL"),
    token: Optional[str] = Query(None, description="Classplus x-access-token"),
    orgCode: Optional[str] = Query(None),
):
    try:
        decoded = unquote(url)
        decoded = _normalize_url(decoded)

        if not token:
            return JSONResponse(
                {"success": False, "error": "token query param required"}
            )

        # Auto-extract orgCode from URL path if caller didn't provide it
        # e.g. media-cdn.classplusapp.com/438039/lc/... → orgCode = "438039"
        if not orgCode:
            orgCode = _extract_org_code_from_url(decoded)
            if orgCode:
                log.info("Auto-extracted orgCode=%s from URL", orgCode)

        async with httpx.AsyncClient(follow_redirects=True) as client:
            sign_data = await _classplus_sign(client, decoded, token, orgCode)
            plain_url, drm_urls = _extract_signed_pieces(sign_data)

            # DRM branch
            if drm_urls and (drm_urls.get("manifestUrl") or drm_urls.get("licenseUrl")):
                mpd_url = drm_urls.get("manifestUrl") or plain_url
                license_url = drm_urls.get("licenseUrl")
                if not mpd_url or not license_url:
                    return JSONResponse(
                        {"success": False, "error": "manifest/license url missing"}
                    )
                try:
                    keys = await _widevine_keys(client, mpd_url, license_url)
                    return JSONResponse({"MPD": mpd_url, "KEYS": keys})
                except Exception as e:
                    log.exception("Widevine error")
                    return JSONResponse(
                        {"success": False, "error": f"widevine: {e}", "MPD": mpd_url}
                    )

            # Non-DRM branch
            if plain_url:
                # Some classplus URLs are still .mpd without drmUrls
                if _is_drm_url(plain_url):
                    # Try a license fetch through the standard widevine endpoint if available
                    return JSONResponse(
                        {
                            "success": False,
                            "error": "DRM URL returned without license info",
                            "MPD": plain_url,
                        }
                    )
                return JSONResponse({"success": True, "url": plain_url})

            return JSONResponse(
                {"success": False, "error": f"unrecognized response: {str(sign_data)[:200]}"}
            )
    except Exception as e:
        log.exception("Golden_Eagle error")
        return JSONResponse({"success": False, "error": str(e)})
