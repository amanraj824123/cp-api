# Classplus Golden_Eagle API (self-hosted, Render-ready)

Drop-in replacement for `https://cp-api-liart.vercel.app/Golden_Eagle`.

## Endpoint

```
GET /Golden_Eagle?url=<ENCODED_CLASSPLUS_URL>&token=<X_ACCESS_TOKEN>
```

Responses match the original API:

- Non-DRM:
  ```json
  { "success": true, "url": "https://signed..." }
  ```
- DRM:
  ```json
  { "MPD": "https://.../master.mpd", "KEYS": ["<kid>:<key>", ...] }
  ```
- Error:
  ```json
  { "success": false, "error": "..." }
  ```

Health:
```
GET /        -> { "ok": true, "cdm_loaded": true }
GET /health
```

## Deploy on Render

1. Push this `api/` folder to a GitHub repo (root of repo OR keep this folder layout and set Render `rootDir = api`).
2. On Render → **New +** → **Web Service** → connect repo.
3. Environment: **Docker**. `render.yaml` already included.
4. Plan: Free is fine to test.
5. Deploy. Your URL will be like:
   `https://cp-golden-eagle-api.onrender.com/Golden_Eagle?url=...&token=...`

## Local test

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
curl "http://localhost:8000/health"
```

## CDM files

`cdm/device_client_id_blob` + `cdm/device_private_key.txt` are used for
Widevine license decryption. You can also drop a single `.wvd` file in `cdm/`
and it will be preferred.

## Bot integration

Set env var `GE_API_BASE` in your bot to your Render URL (e.g.
`https://cp-golden-eagle-api.onrender.com`). The bot will try your API first
and fall back to the public one automatically.
