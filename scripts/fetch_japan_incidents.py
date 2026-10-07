#!/usr/bin/env python3
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, quote

DAYS = 30
OUT = Path("data/incidents.json")
UA = "ransomlook-mcp-japan-incident-collector/2.0"

ATTACK_TERMS = [
    "不正アクセス","サイバー攻撃","ランサム","ランサムウェア","マルウェア",
    "フィッシング","アカウント乗っ取り","侵害","侵入","Web改ざん","DDoS",
    "サポート詐欺","脆弱性を悪用","脆弱性の悪用","認証情報を不正利用",
    "不正利用","情報流出","情報漏えい","情報漏洩","データ流出",
    "unauthorized access","ransomware","malware","account takeover",
    "vulnerability","cyber attack","phishing","DDoS"
]
EXCLUDE_TERMS = [
    "誤送信","所在不明","紛失","元従業員","不正競争防止法","設定ミス",
    "設定不備","生成AI","生成 AI","操作ミス","misconfiguration","insider","loss"
]

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links=[]; self.current=None; self.parts=[]; self.last_date=None
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=="a" and attrs.get("href"):
            self.current=attrs["href"]; self.parts=[]
    def handle_data(self,data):
        s=" ".join(data.split())
        if not s: return
        m=re.search(r"(20\d{2})[/.年-](\d{1,2})[/.月-](\d{1,2})",s)
        if m: self.last_date=f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
        if self.current is not None: self.parts.append(s)
    def handle_endtag(self,tag):
        if tag=="a" and self.current is not None:
            self.links.append((self.current," ".join(self.parts).strip(),self.last_date))
            self.current=None; self.parts=[]

class TableParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.rows=[]; self.row=None; self.cell=None; self.parts=[]
    def handle_starttag(self,tag,attrs):
        if tag=="tr": self.row=[]
        elif tag in ("td","th") and self.row is not None: self.cell=tag; self.parts=[]
    def handle_data(self,data):
        if self.cell is not None: self.parts.append(" ".join(data.split()))
    def handle_endtag(self,tag):
        if tag in ("td","th") and self.cell is not None:
            self.row.append(" ".join(self.parts).strip()); self.cell=None; self.parts=[]
        elif tag=="tr" and self.row is not None:
            if self.row: self.rows.append(self.row)
            self.row=None

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=30) as r:
        if r.status!=200: raise RuntimeError(f"HTTP {r.status}: {url}")
        return r.read().decode("utf-8",errors="replace")

def clean(text): return re.sub(r"\s+"," ",text).strip()

def is_attack(text):
    t=text.lower()
    if not any(k.lower() in t for k in ATTACK_TERMS): return False
    if any(k.lower() in t for k in EXCLUDE_TERMS) and not any(
        k.lower() in t for k in ["不正アクセス","ランサム","サイバー攻撃","マルウェア","情報流出","情報漏えい","情報漏洩"]
    ): return False
    return True

def collect_security_next(cutoff):
    out=[]
    for page in range(1,8):
        url="https://www.security-next.com/category/cat191/cat27"
        if page>1: url+=f"/page/{page}"
        p=LinkParser(); p.feed(fetch(url)); page_old=True
        for href,title,date in p.links:
            full=urljoin(url,href)
            if not title or not date or not re.search(r"security-next\.com/\d+",full): continue
            if date>=cutoff: page_old=False
            if date<cutoff or not is_attack(title): continue
            out.append({"source":"Security NEXT","source_url":full,"published_date":date,"title":clean(title),"attack":True})
        if page_old: break
    return out

def collect_yagura(cutoff):
    url="https://incident.yagurasec.com/"; p=LinkParser(); p.feed(fetch(url))
    out=[]; seen=set()
    for href,title,date in p.links:
        full=urljoin(url,href)
        if "/incidents/" not in full or not date or date<cutoff: continue
        title=clean(title)
        if not title or not is_attack(title): continue
        key=(full,title)
        if key in seen: continue
        seen.add(key); out.append({"source":"Yagura","source_url":full,"published_date":date,"title":title,"attack":True})
    return out

def article_date_from_url(url, fallback):
    m = re.search(r"/(20\\d{2})/(\\d{2})/(\\d{2})/", url)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else fallback

def collect_scannet(cutoff):
    out=[]
    for page in range(1,8):
        url="https://scan.netsecurity.ne.jp/article/" + (f"?page={page}" if page>1 else "")
        p=LinkParser(); p.feed(fetch(url)); page_old=True
        for href,title,date in p.links:
            full=urljoin(url,href)
            if "/article/" not in full or not date: continue
            date = article_date_from_url(full, date)
            if date>=cutoff: page_old=False
            if date<cutoff or not is_attack(title): continue
            title = re.sub(r"^インシデント・情報漏えい\\s+ScanNetSecurity\\s+20\\d{2}\\.\\d{1,2}\\.\\d{1,2}.*?\\s+\\d{1,2}:\\d{2}\\s+", "", clean(title))
            title = re.sub(r"^セキュリティホール・脆弱性\\s+ScanNetSecurity\\s+.*?\\s+", "", title)
            out.append({"source":"ScanNetSecurity","source_url":full,"published_date":date,"title":title,"attack":True})
        if page_old: break
    return out

def collect_smartscope(cutoff):
    url="https://smartscope.blog/en/blog/japan-data-breach-list-tier-2026-09-10/"
    parser=TableParser(); parser.feed(fetch(url)); out=[]
    for row in parser.rows:
        if len(row)<4: continue
        disclosed,org,count,entry=[clean(x) for x in row[:4]]
        m=re.search(r"(Sep|Oct)\s+(\d{1,2})",disclosed)
        if not m: continue
        month=9 if m.group(1)=="Sep" else 10
        date=f"2026-{month:02d}-{int(m.group(2)):02d}"
        if date<cutoff: continue
        if not is_attack(f"{org} {entry}"): continue
        out.append({"source":"SmartScope","source_url":url,"published_date":date,
                    "title":f"{org} — {entry}","organization":org,
                    "affected_count":count,"attack_type":entry,"attack":True})
    return out

def collect_google_news(cutoff):
    queries=[
        "日本 不正アクセス 情報漏えい 企業",
        "日本 サイバー攻撃 情報流出 企業",
        "日本 ランサムウェア 企業",
        "日本 不正アクセス 10月 2026",
        "日本 情報漏えい 10月 2026",
    ]
    out=[]; seen=set()
    for q in queries:
        url="https://news.google.com/rss/search?q="+quote(q+" after:"+cutoff)+"&hl=ja&gl=JP&ceid=JP:ja"
        root=ET.fromstring(fetch(url))
        for item in root.findall("./channel/item"):
            title=clean(item.findtext("title") or "")
            link=item.findtext("link") or ""
            pub=item.findtext("pubDate") or ""
            if not title or not link or not is_attack(title): continue
            bad = ["脆弱性","ゼロデイ","解説","ブリーフィング","相次ぐ","警鐘","逮捕","販売との投稿","事実は確認されず","対策","注意喚起","動向","予測"]
            if any(x in title for x in bad): continue
            if not re.search(r"(不正アクセス|サイバー攻撃|ランサムウェア|ランサムウエア|情報漏えい|情報漏洩|情報流出|乗っ取り|侵入)", title): continue
            try:
                dt=datetime.strptime(pub,"%a, %d %b %Y %H:%M:%S %Z").date().isoformat()
            except Exception:
                try: dt=datetime.strptime(pub,"%a, %d %b %Y %H:%M:%S +0000").date().isoformat()
                except Exception: continue
            if dt<cutoff: continue
            # Google News links are source-specific redirect URLs; keep them for traceability.
            key=(title,link)
            if key in seen: continue
            seen.add(key)
            out.append({"source":"Google News","source_url":link,"published_date":dt,"title":title,"attack":True})
    return out

ORG_ALIASES={
    "sagawa":["佐川急便","sagawa express"],
    "yamato":["ヤマト運輸","ヤマトホールディングス","yamato transport"],
    "timescar":["times car","タイムズカー","park24","パーク24"],
    "yakiniku_king":["焼肉きんぐ","物語コーポレーション","yakiniku king","monogatari"],
    "daiwa":["大和証券","daiwa securities"],
    "daiichi_life":["第一生命","dai-ichi life"],
    "rakuten_drive":["楽天ドライブ","rakuten drive"],
    "citizen":["シチズン時計","citizen watch"],
    "gmo_research":["gmoリサーチ","gmo research","infoq"],
    "mrmax":["ミスターマックス","mrmax"],
    "asahi_kasei":["旭化成","asahi kasei"],
    "helpfeel":["helpfeel","gyazo"],
    "monogatari":["物語コーポレーション","monogatari corporation"],
}

def normalize_org(text):
    t=clean(text).lower()
    for key,aliases in ORG_ALIASES.items():
        if any(a.lower() in t for a in aliases): return key
    t=re.split(r"[、,:：\-—|/]",t,maxsplit=1)[0]
    t=re.sub(r"\([^)]*\)","",t).strip()
    t=re.sub(r"(株式会社|有限会社|合同会社|inc\.?|corp\.?|co\.?\s*ltd\.?)$","",t).strip()
    return re.sub(r"[^a-z0-9一-龥ぁ-んァ-ヶ]","",t)

def extract_organization(text):
    t=clean(text)
    aliases=[
        (r"シチズン時計|CITIZEN","シチズン時計"),
        (r"GMOリサーチ|GMO Research|infoQ","GMOリサーチ＆AI"),
        (r"ミスターマックス|MrMax","ミスターマックス"),
        (r"旭化成","旭化成"),
        (r"楽天ドライブ|Rakuten Drive","楽天モバイル（楽天ドライブ）"),
        (r"焼肉きんぐ|Yakiniku King","物語コーポレーション"),
        (r"PhotoGoods","大興印刷"),
        (r"ビールの縁側","原田産業"),
        (r"Gyazo","Helpfeel"),
        (r"ULTRA MART|円谷プロ","円谷プロダクション"),
        (r"スマチケ|e\+","イープラス"),
        (r"GSS","デジタル庁"),
        (r"佐賀大|佐賀大学","佐賀大学"),
        (r"京王電鉄|京王ストア","京王電鉄"),
        (r"信濃毎日新聞デジタル","信濃毎日新聞"),
        (r"Times Car","パーク24"),
        (r"Sakura Internet","さくらインターネット"),
    ]
    for pattern,name in aliases:
        if re.search(pattern,t,re.I): return name
    m=re.search(r"(?:株式会社|有限会社|合同会社|国立大学法人|学校法人|独立行政法人)[^、。\n]{1,60}?(?=(?:は|が|に|の)\s)",t)
    if m: return clean(m.group(0))
    m=re.search(r"([^、。\n]{2,35}(?:大学|銀行|電鉄|鉄道|新聞|証券|病院|協同組合|ホールディングス|HD|県教育委員会|庁|市役所|区役所))(?:は|が|に|の)",t)
    if m: return clean(m.group(1))
    return None

def incident_org(item):
    return normalize_org(item.get("organization") or extract_organization(item.get("title","")) or item.get("title",""))

def merge_cross_source_incidents(items):
    groups=[]
    for item in sorted(items,key=lambda x:(x["published_date"],x["source"],x["title"])):
        org=incident_org(item)
        try: dt=datetime.fromisoformat(item["published_date"]).date()
        except ValueError:
            groups.append({"items":[item],"org":org,"date":None}); continue
        best=None
        for group in groups:
            if group["org"]==org and group["date"] is not None and abs((dt-group["date"]).days)<=30:
                best=group; break
        if best is None: groups.append({"items":[item],"org":org,"date":dt})
        else:
            best["items"].append(item)
            best["date"]=max(datetime.fromisoformat(x["published_date"]).date() for x in best["items"])
    merged=[]
    for group in groups:
        records=group["items"]
        if len(records)==1:
            item=dict(records[0]); item["sources"]=[item["source"]]; item["source_records"]=[dict(item)]; merged.append(item); continue
        records=sorted(records,key=lambda x:(x["published_date"],x["source"]))
        base=dict(records[0]); base["sources"]=list(dict.fromkeys(x["source"] for x in records))
        base["source_records"]=[dict(x) for x in records]; base["source_count"]=len(base["sources"]); base["merged"]=True
        if not base.get("organization"): base["organization"]=extract_organization(base.get("title",""))
        merged.append(base)
    return merged

def main():
    today=datetime.now(timezone.utc).date()
    cutoff=(today-timedelta(days=DAYS)).isoformat()
    errors={}; incidents=[]
    collectors=[
        ("Security NEXT",collect_security_next),
        ("Yagura",collect_yagura),
        ("ScanNetSecurity",collect_scannet),
        ("SmartScope",collect_smartscope),
        ("Google News",collect_google_news),
    ]
    for name,fn in collectors:
        try: incidents.extend(fn(cutoff))
        except Exception as e: errors[name]=str(e)
    for item in incidents:
        if not item.get("organization"): item["organization"]=extract_organization(item.get("title",""))
    unique={}
    for x in incidents: unique[(x["source"],x["source_url"],x["title"])]=x
    incidents=merge_cross_source_incidents(list(unique.values()))
    incidents.sort(key=lambda x:(x["published_date"],x["title"]),reverse=True)
    payload={
        "source":"Japanese cyber incident sources",
        "retrieved_at":datetime.now(timezone.utc).isoformat(),
        "window_days":DAYS,"cutoff_date":cutoff,"attack_only":True,
        "sources":["Security NEXT","Yagura","ScanNetSecurity","SmartScope","Google News"],
        "count":len(incidents),"source_errors":errors,
        "deduplication":{"same_source_exact":True,"cross_source_merge":True,
            "cross_source_rule":"same normalized organization and publication dates within 30 days",
            "source_records_retained":True},
        "incidents":incidents
    }
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"Wrote {OUT}: {len(incidents)} attack-related items")
    if errors: print("Source errors:",errors)

if __name__=="__main__": main()
