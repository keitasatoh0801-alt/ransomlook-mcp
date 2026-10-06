# RansomLook MCP for ChatGPT

RansomLook の公開APIを、読み取り専用のModel Context Protocol (MCP) serverとして公開します。

## 提供するツール

- `recent_posts(days)` — 指定日数の直近投稿
- `search_posts(query)` — 組織名・ドメイン・グループ等で検索
- `group_details(group)` — ランサムウェアグループ情報
- `actor_profile(actor)` — Threat Actor情報
- `crypto_addresses(group)` — グループに関連する暗号資産アドレス

## 国内サイバーインシデント情報

GitHub Actionsで、RansomLookに加えて国内の公開情報源を定期取得します。

- Security NEXT
- Yagura
- ScanNetSecurity
- SmartScope

`data/incidents.json` は、30日以内の公開情報からサイバー攻撃関連だけを抽出したスナップショットです。誤送信・紛失・設定ミス・内部不正などは対象外です。

## 前提

RansomLookの公開APIは、上記の読み取り用途ではAPIキー不要です。
RansomLookのDB export APIは別途APIキーが必要なので、この初版では公開していません。

## ローカル起動

Python 3.12+ を推奨。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

MCP endpoint:
`http://localhost:8000/mcp`

## Docker

```bash
docker compose up --build
```

## ChatGPTへの接続

ChatGPT側から直接到達できるリモートURLが必要です。
HTTPSで公開したMCP endpointを、ChatGPTの「Create custom MCP server」から登録します。

例:
`https://YOUR-DOMAIN.example/mcp`

認証は、この読み取り専用サーバーだけならNo authenticationでも動きます。
ただしインターネットへ公開する場合は、認証・レート制限・アクセス制御を追加することを推奨します。

## 重要

このサーバーはRansomLookから取得した情報をそのまま返します。
ChatGPT側では、検索結果に存在しない企業・攻撃グループ・日付等を推測しない運用にしてください。
