#!/usr/bin/env python3
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from html import unescape
from pathlib import Path
from urllib.parse import urljoin, quote

DAYS = 30
OUT = Path("data/incidents.json")
UA = "ransomlook-mcp-japan-incident-collector/3.0"
MAX_ARTICLE_CHARS = 18000

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
    m = re.search(r"/(20\d{2})/(\d{2})/(\d{2})/", url)
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
            title = re.sub(r"^インシデント・情報漏えい\s+ScanNetSecurity\s+20\d{2}\.\d{1,2}\.\d{1,2}.*?\s+\d{1,2}:\d{2}\s+", "", clean(title))
            title = re.sub(r"^セキュリティホール・脆弱性\s+ScanNetSecurity\s+.*?\s+", "", title)
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
            if any(x in title for x in [
                "国内不正アクセス","企業や自治体への不正アクセス","なぜ不正アクセス","不正アクセスなぜ",
                "専門家の見解","識者の見解","サイバー攻撃による情報流出続発","日本とデンマークの企業や機関",
                "AIで武装強化されたランサムウエア","自律型サイバー攻撃","自己防衛","ウェビナー","経営層向け",
                "ランサムウェア集団「Qilin」幹部","国際的サイバー攻撃集団「キリン」","ランサムウェア集団「KillSec」",
                "ランサムウェア グループ Qilin","ランサムウェア集団 Qilin","本当に怖い情報流出",
                "警告する","サイバー攻撃の経済学","生成AI事件簿","ターゲットは普通の会社","…も","も…",
                "記事まとめ","ニュースまとめ","セキュリティ動向"
            ]): continue
            # Google News is a discovery source; retain only titles that identify a concrete victim.
            if not extract_organization(title):
                continue
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
        (r"シチズン時計|CITIZEN","シチズン時計"),(r"GMOリサーチ|GMO Research|infoQ","GMOリサーチ＆AI"),
        (r"ミスターマックス|MrMax","ミスターマックス"),(r"旭化成","旭化成"),
        (r"楽天ドライブ|Rakuten Drive","楽天モバイル（楽天ドライブ）"),(r"焼肉きんぐ|Yakiniku King","物語コーポレーション"),
        (r"PhotoGoods","大興印刷"),(r"ビールの縁側","原田産業"),(r"Gyazo","Helpfeel"),
        (r"ULTRA MART|円谷プロ","円谷プロダクション"),(r"スマチケ|e\+","イープラス"),
        (r"GSS","デジタル庁"),(r"佐賀大|佐賀大学","佐賀大学"),(r"京王電鉄|京王ストア","京王電鉄"),
        (r"信濃毎日新聞デジタル","信濃毎日新聞"),(r"Times Car","パーク24"),(r"Sakura Internet","さくらインターネット"),
        (r"KKR京都くに荘","国家公務員共済組合連合会"),
        (r"ニモカ|nimoca","ニモカ"),(r"GMO系|GMO","GMO"),
        (r"大起水産","大起水産"),(r"アバハウス","アバハウスインターナショナル"),
        (r"ジャパンタイムズ","ジャパンタイムズ"),(r"第一ライフ","第一生命"),
        (r"原子力機構|日本原子力研究開発機構","日本原子力研究開発機構"),
        (r"日本エネルギー経済研究所","日本エネルギー経済研究所"),
        (r"佐川急便","佐川急便"),(r"ヤマト運輸","ヤマト運輸"),
        (r"郵便局アプリ","日本郵便"),(r"日本交通","日本交通"),
        (r"セイコーマート","セイコーマート"),(r"カイクラ","シンカ"),
        (r"日本経済新聞社|日経新聞","日本経済新聞社"),(r"日経BP","日経BP"),
        (r"ニッポンレンタカー","ニッポンレンタカーサービス"),(r"ベネワン・プラットフォーム|ベネフィット・ワン","ベネフィット・ワン"),
        (r"ムラウチドットコム","ムラウチドットコム"),
    ]
    hits=[]
    for pattern,name in aliases:
        m=re.search(pattern,t,re.I)
        if m: hits.append((m.start(),name))
    if hits: return min(hits,key=lambda z:z[0])[1]
    patterns=[
        r"((?:株式会社|有限会社|合同会社|国立大学法人|学校法人|独立行政法人)[^、。\n]{1,80}?)(?=(?:は|が|に|の))",
        r"([^、。\n]{2,60}(?:株式会社|有限会社|合同会社|大学法人|学校法人|独立行政法人))(?=(?:は|が|に|の))",
        r"([^、。\n]{2,45}(?:大学|銀行|電鉄|鉄道|新聞|証券|病院|協同組合|連合会|機構|協会|ホールディングス|HD|県教育委員会|庁|市役所|区役所))(?:は|が|に|の)",
    ]
    for pat in patterns:
        m=re.search(pat,t,re.I)
        if m:
            value=clean(m.group(1))
            value=re.sub(r"^(?:インシデント・情報漏えい|ScanNetSecurity)\s+","",value)
            if len(value)>=2: return value
    return None

def extract_service(text, org=None):
    t=clean(text)
    quoted=re.findall(r"[「『]([^」』]{2,80})[」』]",t)
    for x in quoted:
        if not any(k in x for k in ["お知らせ","ご報告","第1報","第2報","最終報"]): return x
    m=re.search(r"((?:Web|EC|公式|オンライン|会員|予約|メール|問い合わせ|問合せ|アプリ|サイト|サーバ|システム)[^、。\n]{1,50})",t,re.I)
    return clean(m.group(1)) if m else None

def extract_incident_fields(text, org=None):
    t=clean(text); lower=t.lower()
    if "ランサム" in t: attack_type="ランサムウェア"
    elif "フィッシング" in t: attack_type="フィッシング"
    elif "ddos" in lower: attack_type="DDoS"
    elif "マルウェア" in t: attack_type="マルウェア"
    elif ("乗っ取り" in t) or ("アカウント" in t and "不正アクセス" in t): attack_type="アカウント侵害"
    elif "不正アクセス" in t or "侵入" in t or "侵害" in t: attack_type="不正アクセス"
    else: attack_type=None
    leak_status="不明"
    if re.search(r"漏えい|漏洩|流出|外部に(転送|送信|流出)|窃取",t): leak_status="確認・可能性あり"
    if re.search(r"(漏えい|漏洩|流出).{0,30}(確認されず|認められず|検出されず|なかった)",t): leak_status="確認されず"
    if re.search(r"(漏えい|漏洩|流出).{0,20}(可能性|おそれ|恐れ)",t): leak_status="可能性あり"
    count=None
    for pat in [r"(?:約|最大約|最大|計)?([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)\s*(?:件|人|名|アカウント|件の個人情報|アカウント情報)",r"([0-9]+(?:\.[0-9]+)?万)\s*(?:件|人|名|アカウント)"]:
        m=re.search(pat,t)
        if m: count=m.group(1); break
    data_types=[]
    for label,terms in {
        "氏名":["氏名","名前"],"住所":["住所"],"電話番号":["電話番号"],"メールアドレス":["メールアドレス"],
        "生年月日":["生年月日"],"クレジットカード情報":["カード情報","クレジットカード"],"口座情報":["口座情報","銀行口座"],
        "認証情報":["パスワード","認証情報"],"問い合わせ内容":["問い合わせ内容","問合せ内容"],
        "顧客情報":["顧客情報"],"従業員情報":["従業員情報"],"会員情報":["会員情報"]}.items():
        if any(x in t for x in terms): data_types.append(label)
    return {"attack_type":attack_type,"leak_status":leak_status,"leak_count":count,"leaked_data":list(dict.fromkeys(data_types)),
            "incident_summary":t[:500]+("…" if len(t)>500 else "")}

class ArticleTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_article=0
        self.parts=[]
        self.meta_description=""
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=="article": self.in_article+=1
        if tag=="meta" and attrs.get("name","").lower()=="description":
            self.meta_description=unescape(attrs.get("content",""))
    def handle_endtag(self,tag):
        if tag=="article" and self.in_article>0: self.in_article-=1
    def handle_data(self,data):
        if self.in_article>0:
            x=" ".join(data.split())
            if x: self.parts.append(x)

def fetch_article_text(url):
    try:
        html=fetch(url)
        parser=ArticleTextParser()
        parser.feed(html)
        text=clean(" ".join(parser.parts))
        if text:
            return text[:MAX_ARTICLE_CHARS]
        if parser.meta_description:
            return clean(parser.meta_description)[:MAX_ARTICLE_CHARS]
        return ""
    except Exception:
        return ""

def enrich_incidents(items):
    targets=[x for x in items if x.get("source")!="SmartScope" and x.get("source_url") and "news.google.com" not in x.get("source_url","")]
    enriched={}
    def one(item):
        body=fetch_article_text(item["source_url"])
        title_text=clean(item.get("title",""))
        source_text=clean(" ".join([title_text,body]))
        item=dict(item)
        org=extract_organization(title_text) or extract_organization(body[:5000]) or item.get("organization")
        if org: item["organization"]=org
        item["service"]=extract_service(title_text,org) or extract_service(body[:5000],org)
        title_fields=extract_incident_fields(title_text,org)
        body_fields=extract_incident_fields(body[:5000],org) if body else {}
        item["attack_type"]=title_fields.get("attack_type") or body_fields.get("attack_type")
        item["leak_status"]=body_fields.get("leak_status") if body_fields.get("leak_status")!="不明" else title_fields.get("leak_status","不明")
        item["leak_count"]=body_fields.get("leak_count") or title_fields.get("leak_count")
        item["leaked_data"]=body_fields.get("leaked_data") or title_fields.get("leaked_data",[])
        item["incident_summary"]=body[:500] if body else title_text
        return item
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures={ex.submit(one,x):i for i,x in enumerate(targets)}
        for f in as_completed(futures):
            i=futures[f]
            try: enriched[i]=f.result()
            except Exception: enriched[i]=targets[i]
    target_ids={id(x):i for i,x in enumerate(targets)}
    return [enriched.get(target_ids[id(x)],x) if id(x) in target_ids else x for x in items]

def incident_org(item):
    return normalize_org(item.get("organization") or extract_organization(item.get("incident_summary","") or item.get("title","")) or item.get("title",""))

def _tokens(text):
    return set(re.findall(r"[一-龥ぁ-んァ-ヶA-Za-z0-9]{2,}",clean(text).lower()))

def same_incident(a,b):
    if incident_org(a) != incident_org(b): return False
    try:
        da=datetime.fromisoformat(a["published_date"]).date()
        db=datetime.fromisoformat(b["published_date"]).date()
    except Exception:
        return False
    if abs((da-db).days)>30: return False

    ta=_tokens(a.get("title",""))
    tb=_tokens(b.get("title",""))
    overlap=len(ta&tb)/max(1,min(len(ta),len(tb))) if ta and tb else 0

    sa=normalize_org(a.get("service") or "")
    sb=normalize_org(b.get("service") or "")
    ca=a.get("leak_count")
    cb=b.get("leak_count")
    aa=a.get("attack_type")
    ab=b.get("attack_type")

    # Explicitly keep separate incidents separate.
    contradiction=("別の不正アクセス" in a.get("title","") or "別の不正アクセス" in b.get("title","") or
                    "異なる手法" in a.get("title","") or "異なる手法" in b.get("title","") or
                    "別件" in a.get("title","") or "別件" in b.get("title",""))
    if contradiction: return False

    if ca and cb and ca==cb and aa and ab and aa==ab:
        return True
    if overlap>=0.60:
        return True
    if sa and sb and (sa==sb or sa in sb or sb in sa) and aa and ab and aa==ab and overlap>=0.25:
        return True
    return False

def merge_cross_source_incidents(items):
    groups=[]
    for item in sorted(items,key=lambda x:(x["published_date"],x["source"],x["title"])):
        best=None
        for group in groups:
            if same_incident(item,group["items"][0]):
                best=group
                break
        if best is None:
            groups.append({"items":[item]})
        else:
            best["items"].append(item)

    merged=[]
    for group in groups:
        records=sorted(group["items"],key=lambda x:(x["published_date"],x["source"]))
        base=dict(records[-1])
        base["sources"]=list(dict.fromkeys(x["source"] for x in records))
        base["source_records"]=[dict(x) for x in records]
        base["source_count"]=len(base["sources"])
        base["merged"]=len(records)>1
        # Prefer the richest fields across all source records.
        for field in ["organization","service","attack_type","leak_status","leak_count","leaked_data","incident_summary"]:
            if not base.get(field):
                for x in reversed(records):
                    if x.get(field):
                        base[field]=x[field]
                        break
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
    incidents=enrich_incidents(incidents)
    for item in incidents:
        if not item.get("organization"):
            item["organization"]=extract_organization(item.get("incident_summary","") or item.get("title",""))
        if not item.get("incident_summary"):
            item.update(extract_incident_fields(item.get("title",""), item.get("organization")))
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
            "cross_source_rule":"same normalized organization plus incident fingerprint; date proximity is supporting evidence",
            "source_records_retained":True},
        "incidents":incidents
    }
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"Wrote {OUT}: {len(incidents)} attack-related items")
    if errors: print("Source errors:",errors)

if __name__=="__main__": main()
