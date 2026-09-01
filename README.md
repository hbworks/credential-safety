# Credential Safety Plugin for Hermes Agent

Hermes Agent における認証情報（APIキー、トークン、パスワードなど）の漏洩を防止する多層防御セキュリティプラグインです。  
[GitHub Issue #20785](https://github.com/NousResearch/hermes-agent/issues/20785) で報告された「チャット出力や思考/推論ブロック内での認証情報漏洩（特に修正報告等のメタディスカッション時）」に対するパッチ・防御機能を提供します。

---

## 🎯 背景と課題（なぜプロンプト指示だけでは防げないのか）

1. **メタディスカッションの罠**:
   * エージェントがシークレット漏洩を修正した際、「〇〇のパスワード（平文）を修正しました」と修正報告の中で平文を再度引用してしまう。
2. **思考・推論ブロック（`<think>`）の可視化**:
   * Discord、Telegram、CLI などで思考ブロックが表示される環境において、推論過程で引用された平文シークレットがそのまま露出する。
3. **プロンプト指示の限界**:
   * モデルに対する事後的なプロンプト指示（「認証情報を出力するな」）は、解説や思考プロセス内で高確率で破られるため、**パイプライン出力層での機械的なサニタイズ（Redaction）** が不可欠です。

---

## ⚙️ 理論上の動作（多層防御アーキテクチャ）

本プラグインは、以下の **4層の防御パイプライン** によって認証情報の流入・露出を遮断します。

```
[ ツール実行 / ターミナル ]
       │
       ▼
┌─────────────────────────────────────────┐
│ Layer 1 & 2: 入力サニタイズ             │
│  ・transform_tool_result                │
│  ・transform_terminal_output            │
│  → .env / printenv / JSON 等をマスク    │
└─────────────────────────────────────────┘
       │
       ▼ （シークレットが除外された状態で渡る）
┌─────────────────────────────────────────┐
│ LLM 推論 & 思考プロセス (<think>)      │
└─────────────────────────────────────────┘
       │
       ▼ （万が一モデルが平文を出力しようとした場合）
┌─────────────────────────────────────────┐
│ Layer 3: 出力サニタイズ                 │
│  ・transform_llm_output                 │
│  → 既知トークン形式スキャン            │
│  → メタディスカッション自然言語置換     │
│  → 思考ブロック (<think>) 内の強制マスク│
└─────────────────────────────────────────┘
       │
       ▼
[ ユーザー / クライアント (CLI, Discord, Telegram) ]
```

---

### 各レイヤーの詳細仕様

#### 1. ツール結果のサニタイズ (`transform_tool_result`)
* **動作タイミング**: エージェントが各種ツール（ファイル読み込み、APIリクエスト等）を実行した直後。
* **動作内容**:
  * `KEY=VALUE` 形式の設定値からシークレット値を `***` に置換。
  * JSON レスポンスに含まれるクレデンシャルフィールド（`api_key`, `secret`, `access_token` 等）の **キー名を維持したまま値のみをマスク**（例: `"api_key": "***"`）。
  * 既知のシークレットシグネチャを直接置換。
* **目的**: そもそも LLM のコンテキスト（推論メモリ）に平文シークレットが流入することを入口で遮断します。

#### 2. ターミナル出力のサニタイズ (`transform_terminal_output`)
* **動作タイミング**: シェルコマンド実行の標準出力・標準エラー出力取得時。
* **動作内容**:
  * `env`, `printenv`, `export`, `cat .env` などの環境変数・機密ファイル表示コマンドの出力を検出・サニタイズ。

#### 3. LLM出力・思考プロセスのサニタイズ (`transform_llm_output`)
* **動作タイミング**: モデルがテキスト（最終回答および `<think>` 思考ブロック）を生成し、ユーザーへ配信する直前。
* **動作内容**:
  1. **既知トークン直接スキャン**:
     文脈によらず、OpenAI / Anthropic / AWS / GitHub / Slack / JWT / Private Key などのフォーマットを正規表現で検出し即座に `***` に置換。
  2. **コードブロック / 設定値置換**:
     モデルが出力したコードスニペット内の `KEY=value` や `key: value` をマスク。
  3. **メタディスカッション自然言語置換**:
     「パスワードは `XXXX` です」「The password was changed to `XXXX`」などの解説文パターンをエントロピー/構造判定（`_looks_like_secret`）と組み合わせてピンポイントでマスク。

#### 4. コア層パターン登録 (`ctx.register_redaction_patterns`)
* **動作タイミング**: プラグイン初期化時（`register(ctx)`）。
* **動作内容**:
  * Hermes 本体のマスキングエンジンが対応している場合、カスタム正規表現パターンを一括登録してコアレベルでフィルタリングを有効化。

---

## 📦 対応している主なシークレット形式

* **AI & Cloud Providers**:
  * OpenAI / Anthropic: `sk-...`, `sk-ant-...`, `sk-proj-...`
  * Google: `AIza...` (Gemini/Maps/Firebase), `ya29...` (OAuth Access Token)
  * HuggingFace: `hf_...`
  * AWS: `AKIA[0-9A-Z]{16}`
* **Code Hosting & CI/CD**:
  * GitHub: `ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...`, `github_pat_...` (Fine-grained PAT)
  * GitLab: `glpat-...`
* **SaaS & Communication APIs**:
  * Stripe: `sk_live_...`, `rk_live_...` (本番/制限キー)
  * SendGrid: `SG....`
  * Twilio: `SK...` (API Key SID), `AC...` (Account SID)
  * Slack: `xoxb-...`, `xoxp-...` (User/Bot), `xapp-...` (App-level Token)
* **Standard Cryptographic & Auth Headers**:
  * JWT Tokens: `eyJ...` (多段セグメント構造)
  * Private Key Headers: `-----BEGIN RSA/EC/OPENSSH PRIVATE KEY-----`
  * Authorization Headers: `Bearer ...`
* **汎用設定形式**: `API_KEY=...`, `PASSWORD=...`, `"token": "..."`


---

## 🚀 インストールと設定

### 1. プラグインの配置
Hermes のプラグインディレクトリに配置します：
```bash
cp -r credential-safety ~/.hermes/plugins/
```

### 2. プロファイルで有効化
使用するプロファイル設定（`config.yaml` または `profiles/<profile_name>.yaml`）の `plugins` セクションに追加します：
```yaml
plugins:
  - credential-safety
```

---

## 🔍 過去の会話DB・ログ監査ツール (`scan_credentials.py`)

プラグイン環境とは独立して、**過去の会話DB（SQLite）やログファイル（JSON/JSONL/TXT）に平文の認証情報が残っていないかを一括スキャン・自動修復（サニタイズ）する単体CLIツール**が付属しています。

外部依存ライブラリなし（Python 3 標準ライブラリのみ）で動作します。

### 🌟 主な機能
1. **各プロファイルの認証情報（`.env`, `auth.json`）の自動ロード＆完全一致追跡**:
   * `~/.hermes/profiles/*/.env` や `auth.json` に設定されている実シークレットを自動収集し、**DBやログにその文字列がそのまま漏れていないかを偽陽性（誤検知）ゼロで最優先照合**します。
2. **未知のシークレット・パスワードのヒューリスティクス検知**:
   * 会話中にユーザーが直接教えたDBパスワードや動的発行トークンも、高精度シャノンエントロピー＋文字種分析で捕捉。
3. **安全設計**:
   * `auth.json` や `.env` などの正規設定ファイル自体はスキャン対象外として保護され、`--fix` 時にも誤って上書き破壊されることはありません。


### 使い方

#### 1. 監査スキャン（読み取りのみ）
デフォルトで `~/.hermes/` およびカレントディレクトリ内のすべての DB/ログファイルを自動探索します：
```bash
python3 credential-safety/scan_credentials.py
```

特定の DB やディレクトリを指定する場合：
```bash
python3 credential-safety/scan_credentials.py ~/.hermes/history.sqlite ./logs/
```

#### 2. 自動マスキング・修復 (`--fix`)
SQLite DB 内で検出されたシークレットを自動的に `***` で上書き修復します（※実行前に自動で `.bak` バックアップが作成されます）：
```bash
python3 credential-safety/scan_credentials.py ~/.hermes/history.sqlite --fix
```

#### 3. JSON 形式での出力
CI/CD やスクリプト連携用に JSON で結果を出力できます：
```bash
python3 credential-safety/scan_credentials.py --json
```

---

## 🧪 テストの実行

プラグイン単体でマスキング精度のユニットテストを実行できます：
```bash
python3 credential-safety/tests/test_credential_safety.py -v
```

---

## 🎯 本番環境での動作確認・チェック手順

プラグインを有効化した Hermes Agent（チャット画面）で、正常に認証情報が防御されているか確認するためのテスト手順です。

### 1. チャット対話での動作確認（4つのシナリオ）

Hermes を起動し、以下のプロンプトをチャットに入力してエージェントの挙動を確認します：

#### シナリオ①: メタディスカッション（復唱遮断テスト）
エージェントに「設定したキーを復唱させる」プロンプトを投げます。
```text
先ほど設定したOpenAIのキーは sk-proj-abcdef1234567890abcdef1234567890abcdef123456 です。設定内容を日本語で確認してください。
```
* **期待される結果**: 回答本文（および `<think>` 思考ブロック）内のキーが **`***` に自動マスキング** されること。

#### シナリオ②: ツール実行結果（環境変数ダンプの遮断テスト）
ターミナルツールで機密情報を含む出力をさせた際のマスキングを確認します。
```text
ターミナルで echo "MY_SECRET_KEY=sk-1234567890abcdef1234567890abcdef" を実行して結果を見せて
```
* **期待される結果**: ツール実行結果の表示が `MY_SECRET_KEY=***` にマスクされてチャットに届くこと。

#### シナリオ③: 主要SaaSトークンのマスキングテスト
Google API Key や GitHub Fine-grained PAT などの主要トークン形式を投げます。
```text
以下の設定ファイルを出力して:
GOOGLE_API_KEY=AIzaSyYourGoogleApiKey1234567890abcdef
GITHUB_TOKEN=github_pat_11SampleToken01234567890ab_samplegithubtokenvalue1234567890abcdefghijklmnopqr
```
* **期待される結果**: トークンの値部分がピンポイントで `***` に置換されること。


#### シナリオ④: 誤検知（False Positive）が起きないことの確認
ドキュメント例やプレースホルダー値が正常に出力されることを確認します。
```text
Mem0プラグインをセットアップするための .env 設定例と echo コマンドを教えて
```
* **期待される結果**: `echo "MEM0_API_KEY=your-admin-api-key" >> ~/.hermes/.env` が `***` に化けず、そのまま読める形で出力されること。

---

### 2. 会話後の DB・ログ監査（クリーンネス確認）

上記のテスト対話が完了した後、過去ログ・DB に平文が一切残っていないかをスキャナーで検証します：

```bash
python3 ~/.hermes/plugins/credential-safety/scan_credentials.py
```

出力結果が以下のように `✅ No credential leaks found!` となっていれば、本番環境でも平文流出がゼロで安全に稼働していることが確認できます：

```text
🔍 Scanning for credential leaks...
  • Target: /Users/masato/.hermes
  🔑 Loaded 12 authentic secret(s) from profile configs for exact-match tracking

----------------------------------------------------------------------
✅ No credential leaks found! All scanned databases and logs are clean.
----------------------------------------------------------------------
Summary: Checked 278 file(s) across 444,090 record/line entries.
```


