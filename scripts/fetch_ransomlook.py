#!/usr/bin/env python3
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_BASE = os.getenv("RANSOMLOOK_API", "https://www.ransomlook.io/api")
DAYS = int(os.getenv("RANSOMLOOK_DAYS", "30"))
OUT = Path(os.getenv("RANSOMLOOK_OUTPUT", "data/recent_posts.json"))

if not 1 <= DAYS <= 30:
    raise SystemExit("RANSOMLOOK_DAYS must be between 1 and 30")

url = f"{API_BASE}/posts?{urllib.parse.urlencode({'days': DAYS})}"
req = urllib.request.Request(url, headers={"User-Agent": "ransomlook-github-actions/1.0"})

with urllib.request.urlopen(req, timeout=30) as resp:
    if resp.status != 200:
        raise SystemExit(f"RansomLook returned HTTP {resp.status}")
    data = json.load(resp)

payload = {
    "source": "RansomLook",
    "api_endpoint": url,
    "retrieved_at": datetime.now(timezone.utc).isoformat(),
    "days": DAYS,
    "count": len(data) if isinstance(data, list) else None,
    "posts": data,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {OUT} with {payload['count']} posts")
