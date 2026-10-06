#!/usr/bin/env python3
import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

DAYS = 30
OUT = Path("data/incidents.json")
UA = "ransomlook-mcp-japan-incident-collector/1.1"

ATTACK_TERMS = [
    "不正アクセス", "サイバー攻撃", "ランサム", "ランサムウェア",
    "マルウェア", "フィッシング", "アカウント乗っ取り", "アカウントへの不正アクセス",
    "侵害", "侵入", "Web改ざん", "改ざん被害", "DDoS", "サポート詐欺",
    "脆弱性を悪用", "脆弱性の悪用", "認証情報を不正利用", "不正利用",
    "unauthorized access", "ransomware", "malware", "account takeover",
    "vulnerability", "cyber attack", "phishing", "DDoS", "social engineering"
]
EXCLUDE_TERMS = [
    "誤送信", "所在不明", "紛失", "元従業員", "不正競争防止法",
    "設定ミス", "設定不備", "生成AI", "生成 AI", "操作ミス",
    "misconfiguration", "error, insider or loss", "insider", "loss"
]

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.current = None
        self.parts = []
        self.last_date = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.current = attrs["href"]
            self.parts = []

    def handle_data(self, data):
        s = " ".join(data.split())
        if not s:
            return
        m = re.search(r"(20\d{2})[/.年-](\d{1,2})[/.月-](\d{1,2})", s)
        if m:
            self.last_date = f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
        if self.current is not None:
            self.parts.append(s)

    def handle_endtag(self, tag):
        if tag == "a" and self.current is not None:
            text = " ".join(self.parts).strip()
            self.links.append((self.current, text, self.last_date))
            self.current = None
            self.parts = []

class TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = None
        self.cell = None
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = tag
            self.parts = []

    def handle_data(self, data):
        if self.cell is not None:
            self.parts.append(" ".join(data.split()))

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join(self.parts).strip())
            self.cell = None
            self.parts = []
        elif tag == "tr" and self.row is not None:
            if self.row:
                self.rows.append(self.row)
            self.row = None

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status}: {url}")
        return r.read().decode("utf-8", errors="replace")

def clean(text):
    return re.sub(r"\s+", " ", text).strip()

def is_attack(title):
    if not any(k.lower() in title.lower() for k in ATTACK_TERMS):
        return False
    if any(k.lower() in title.lower() for k in EXCLUDE_TERMS) and not any(
        k.lower() in title.lower() for k in ["不正アクセス", "ランサム", "サイバー攻撃", "マルウェア"]
    ):
        return False
    return True

def collect_security_next(cutoff):
    out = []
    for page in range(1, 8):
        url = "https://www.security-next.com/category/cat191/cat27"
        if page > 1:
            url += f"/page/{page}"
        p = LinkParser()
        p.feed(fetch(url))
        page_old = True
        for href, title, date in p.links:
            if not title or not date:
                continue
            full = urljoin(url, href)
            if not re.search(r"security-next\.com/\d+", full):
                continue
            if date >= cutoff:
                page_old = False
            if date < cutoff:
                continue
            title = clean(title)
            if not is_attack(title):
                continue
            out.append({"source": "Security NEXT", "source_url": full,
                        "published_date": date, "title": title, "attack": True})
        if page_old:
            break
    return out

def collect_yagura(cutoff):
    url = "https://incident.yagurasec.com/"
    p = LinkParser()
    p.feed(fetch(url))
    out, seen = [], set()
    for href, title, date in p.links:
        full = urljoin(url, href)
        if "/incidents/" not in full or not date or date < cutoff:
            continue
        title = clean(title)
        if not title or not is_attack(title):
            continue
        key = (full, title)
        if key in seen:
            continue
        seen.add(key)
        out.append({"source": "Yagura", "source_url": full,
                    "published_date": date, "title": title, "attack": True})
    return out

def collect_scannet(cutoff):
    out = []
    for page in range(1, 8):
        url = "https://scan.netsecurity.ne.jp/article/"
        if page > 1:
            url += f"?page={page}"
        p = LinkParser()
        p.feed(fetch(url))
        page_old = True
        for href, title, date in p.links:
            full = urljoin(url, href)
            if "/article/" not in full or not date:
                continue
            if date >= cutoff:
                page_old = False
            if date < cutoff:
                continue
            title = clean(title)
            if not title or not is_attack(title):
                continue
            out.append({"source": "ScanNetSecurity", "source_url": full,
                        "published_date": date, "title": title, "attack": True})
        if page_old:
            break
    return out

def collect_smartscope(cutoff):
    url = "https://smartscope.blog/en/blog/japan-data-breach-list-tier-2026-09-10/"
    parser = TableParser()
    parser.feed(fetch(url))
    out = []
    for row in parser.rows:
        if len(row) < 4:
            continue
        disclosed, org, count, entry = [clean(x) for x in row[:4]]
        m = re.search(r"(Sep|Oct)\s+(\d{1,2})", disclosed)
        if not m:
            continue
        month = 9 if m.group(1) == "Sep" else 10
        year = 2026
        date = f"{year:04d}-{month:02d}-{int(m.group(2)):02d}"
        if date < cutoff:
            continue
        # This English SmartScope table is specifically the 18 cases
        # with 100,000+ affected records/accounts/people. The table is part of
        # SmartScope's breach/unauthorized-access tracker, so rows such as
        # "Entry point not stated" are still cyber incidents; do not discard
        # them merely because the entry point is unknown.
        out.append({
            "source": "SmartScope",
            "source_url": url,
            "published_date": date,
            "title": f"{org} — {entry}",
            "organization": org,
            "affected_count": count,
            "attack_type": entry,
            "attack": True
        })
    return out

def main():
    today = datetime.now(timezone.utc).date()
    cutoff = (today - timedelta(days=DAYS)).isoformat()
    errors = {}
    incidents = []
    collectors = [
        ("Security NEXT", collect_security_next),
        ("Yagura", collect_yagura),
        ("ScanNetSecurity", collect_scannet),
        ("SmartScope", collect_smartscope),
    ]
    for name, fn in collectors:
        try:
            incidents.extend(fn(cutoff))
        except Exception as e:
            errors[name] = str(e)

    unique = {}
    for x in incidents:
        unique[(x["source"], x["source_url"], x["title"])] = x
    incidents = list(unique.values())
    incidents.sort(key=lambda x: (x["published_date"], x["source"], x["title"]), reverse=True)

    payload = {
        "source": "Japanese cyber incident sources",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "window_days": DAYS,
        "cutoff_date": cutoff,
        "attack_only": True,
        "sources": ["Security NEXT", "Yagura", "ScanNetSecurity", "SmartScope"],
        "count": len(incidents),
        "source_errors": errors,
        "incidents": incidents
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT}: {len(incidents)} attack-related items")
    if errors:
        print("Source errors:", errors)

if __name__ == "__main__":
    main()
