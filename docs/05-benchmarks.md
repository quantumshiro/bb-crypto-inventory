# 5. ベンチマーク設計

## 5.1 基本方針

最終的には Phase 0-3 を含む包括的なブラックボックス暗号インベントリベンチマークを目指すが、**最初に固定すべきなのは Phase 0+1 の URL-scoped benchmark と、続く Phase 2 の discovery benchmark** である。

理由は次の通り：

1. **自社サービス URL 入力という運用前提に最も近い**
   - 利用者は「自分の HTTPS edge URL」を入力する想定であり、まず必要なのはその URL から直接観測できる情報の評価である
2. **再現性が高い**
   - Header / certificate / TLS protocol / cipher suite は環境差分が比較的小さく、Ground Truth を固定しやすい
3. **実装依存の少ない基準線になる**
   - Application Layer や Oracle 系の benchmark は request template や payload 設計に依存しやすい
4. **製品価値が高い**
   - TLS posture と certificate inventory は、それだけで実務的な価値がある

したがって benchmark rollout は以下の順序にする：

| 段階 | スコープ | 目的 |
|------|---------|------|
| **Phase01 MVP** | Recon + Protocol Layer | まず安定した基準スイートを作る |
| **Phase02 MVP** | App surface discovery | 暗号関連 endpoint を見つけて分類できるかを測る |
| **Phase03 MVP** | App misuse classification | 見つけた surface を bounded probe で誤分類なく判断できるかを測る |
| Phase04 Suite | Oracle / Timing | 許諾環境向けの深い動的検査を測る |

## 5.2 Phase01 MVP の評価境界

### 評価モード

Phase01 MVP は **URL-scoped** とする。

- 入力は `https://service.example.com` のような **明示的な edge URL**
- Phase 0 で評価するのは、その URL から直接得られる偵察情報
- 近隣ポート探索やネットワーク全体 discovery は **今回の scoring 対象外**

この定義にすることで、「URL しか知らない相手のネットワークを広く調べる benchmark」ではなく、**自社 edge URL に対する暗号 posture 評価 benchmark** として安定化できる。

### scanner contract

Phase01 MVP では、「何をしてよいか」だけでなく「何を要求しないか」も固定する。

**要求する capability**

- HTTPS header fetch
- certificate chain extraction
- TLS version testing
- TLS cipher / PFS posture assessment
- SSL Labs style grade computation

**要求しない capability**

- 隣接ポート探索
- SSH 列挙
- OpenAPI 発見
- app-layer crypto misuse 検出
- oracle / timing / randomness 検査

この制約を benchmark に明記する理由は、Phase 0+1 の benchmark を「総合スキャナ能力テスト」ではなく、**edge posture assessment capability test** として純化するためである。

### Phase 0 で採点する項目

| 項目 | 例 |
|------|----|
| HTTP security headers | HSTS の有無 |
| Certificate metadata | 鍵種別、鍵長、署名アルゴリズム、PQ 脆弱性 |
| Basic service fingerprint | HTTPS edge であること、HTTP 応答が返ること |

### Phase 1 で採点する項目

| 項目 | 例 |
|------|----|
| Supported protocol versions | TLS 1.0 / 1.1 / 1.2 / 1.3 |
| Cipher suite posture | RC4, 3DES, static RSA, AEAD only など |
| PFS | ECDHE/DHE の有無 |
| TLS grade | SSL Labs v2009r 相当スコア |

### リクエスト予算

Phase01 MVP は低リクエストで成立するべきである。

| 種類 | 推奨上限 |
|------|---------|
| Header fetch | 2 req |
| Certificate extraction | 2 handshakes |
| Version testing | 4 handshakes |
| Cipher / posture testing | 8 handshakes |
| **合計** | **16 actions / URL 程度** |

大量プロービングはこの phase では不要であり、benchmark でも推奨しない。

## 5.3 準拠するスタンダード

### 脆弱性分類

| 本 benchmark | 参考元 | CWE |
|-------------|--------|-----|
| NoHSTS | OWASP WSTG-CRYP-01 | CWE-319 |
| WeakProtocolVersion | OWASP WSTG-CRYP-01 | CWE-326 |
| InsecureCipherSuite | CamBench Rule 1 相当 + OWASP WSTG-CRYP-01 | CWE-326, CWE-327 |
| NoPFS | TLS config hardening | CWE-320 |
| WeakKeyLength | CamBench Rule 2 相当 | CWE-326 |
| WeakSignatureAlgorithm | Certificate metadata hardening | CWE-327 |

### TLS スコアリング

**Qualys SSL Labs Rating Guide v2009r** に準拠：

```text
総合スコア = Protocol (30%) + Key Exchange (30%) + Cipher Strength (40%)
```

グレードキャップ：

- RC4 → max C
- 3DES / 64-bit block → max C
- non-PFS accepted → max B
- TLS 1.0 / 1.1 → max B

`A+` は、最終 grade が `A` で、かつ `Strict-Transport-Security` が存在し、
`max-age >= 15552000` の場合にのみ与える。

## 5.4 Phase01 MVP ターゲット

### ポジティブターゲット

Phase01 MVP では、1つの weak HTTPS edge に複数の独立 benchmark ID を割り当てる。
同じ URL を使っても、**何を検出できたか** を category 単位で独立採点する。

| ID | 内容 | チャネル | 期待結果 |
|----|------|---------|---------|
| BM-09 | Weak TLS configuration | CH1 | WeakProtocolVersion, InsecureCipherSuite, NoPFS, Grade C |
| BM-11 | HSTS 欠如 | Recon | NoHSTS |
| BM-12 | RSA-1024 証明書 | Recon | WeakKeyLength |
| BM-13 | SHA-1 署名証明書 | Recon | WeakSignatureAlgorithm |

### ネガティブコントロール

| ID | 内容 | 期待結果 |
|----|------|---------|
| NC-04 | TLS 1.3 only + AEAD + PFS + HSTS + RSA-2048/SHA-256 cert | Phase 0+1 finding なし、Grade A+ |

## 5.5 インフラストラクチャ

```text
Docker Compose:
├── vuln-app      : HTTP upstream app (port 9000)
├── nginx-weak    : Weak HTTPS edge (port 9443)
└── nginx-strong  : Strong HTTPS edge (port 9444)
```

### weak edge (`nginx-weak`)

- TLS 1.0 / 1.1 / 1.2 許可
- weak cipher suites を含む
- PFS posture を弱くする
- HSTS なし
- **RSA-1024 + SHA-1 self-signed certificate**

### strong edge (`nginx-strong`)

- TLS 1.3 only
- AEAD only
- HSTS あり
- **RSA-2048 + SHA-256 self-signed certificate**

## 5.6 スコアリング

### 主要指標

| 指標 | 説明 |
|------|------|
| Precision | 報告 finding のうち正しいものの割合 |
| Recall | 期待 finding のうち検出できた割合 |
| F1 Score | Precision / Recall の調和平均 |
| Confidence Calibration | 期待最小 confidence を満たしたか |
| SSL Labs Grade Accuracy | 期待 grade と計算 grade の一致 |
| Detection Latency | 1 target あたりの検出時間 |

### Phase01 MVP での判定単位

- `BM-09` は CH1 の protocol/cipher/PFS posture を採点
- `BM-11` は HSTS 欠如のみを採点
- `BM-12` は certificate key length のみを採点
- `BM-13` は certificate signature algorithm のみを採点
- `NC-04` は false positive の抑制を採点

### マッチング契約

単に category が一致しただけでは十分ではない。各 benchmark で最低限の evidence を要求する。

| Benchmark | category 一致に加えて必要な evidence |
|-----------|-----------------------------------|
| BM-09 | protocol list, representative weak suite, PFS 判定根拠, grade または grade 入力 |
| BM-11 | HSTS 不在の response headers |
| BM-12 | 公開鍵種別と鍵長 |
| BM-13 | 証明書署名アルゴリズム |
| NC-04 | false positive なし |

`NoPFS` は「PFS を一切サポートしないこと」ではなく、**少なくとも1つの non-PFS handshake を受け入れること** と定義する。
この定義により、mixed posture の edge でも benchmark 判定がぶれない。

### release gate

Phase01 を「固まった」とみなす条件は、少なくとも以下とする：

- Precision `>= 0.95`
- Recall `>= 0.90`
- NC-04 false positive `= 0`
- SSL grade accuracy `= 100%`
- fresh container での繰り返し実行に対して結果が安定

### repeated-run protocol

1. benchmark コンテナ起動
2. `phase01` 実行
3. コンテナを破棄して再起動
4. これを最低 10 回繰り返す

追跡する値：

- target ごとの検出率
- confidence の分散
- runtime の分散
- TLS grade の一貫性

## 5.7 Phase02 Discovery Suite

Phase02 は **base-URL-scoped discovery benchmark** とする。

- 入力は `http://service.example.com/` のような **明示的な base URL**
- scoring 対象は same-origin の service index / OpenAPI から取れる candidate endpoint
- app-layer misuse の判定そのものはまだ採点しない

### Phase02 で要求する capability

- service index fetch
- OpenAPI descriptor fetch
- candidate endpoint extraction
- endpoint path / method normalization
- crypto-relevant surface classification

descriptor に `surface_kind` / `crypto_relevant` や OpenAPI vendor extension
`x-bbci-surface-kind` / `x-bbci-crypto-relevant` が存在する場合は、それを
heuristic より優先する。

### Phase02 で採点する surface kind

| Surface Kind | 例 |
|-------------|----|
| `encryption_oracle` | `/api/encrypt`, `/api/encrypt-cbc-static`, `/api/encrypt-strong` |
| `hash_oracle` | `/api/hash`, `/api/hash-sha1`, `/api/hash-strong` |
| `token_issuer` | `/api/token`, `/api/token-secure` |
| `decryption_oracle` | `/api/decrypt` |
| `jwt_auth_surface` | `/api/auth`, `/api/auth-rsa` |
| `hmac_verifier` | `/api/verify-hmac`, `/api/verify-hmac-secure` |

### Phase02 ポジティブターゲット

Phase02 では later phase の脆弱/安全 endpoint の両方を **relevant surface** として採点する。
検出対象は vulnerability ではなく、「後続検査に回すべき surface を見つけられたか」である。

| ID | Endpoint | 期待 surface kind |
|----|----------|-------------------|
| D-01 | `/api/encrypt` | `encryption_oracle` |
| D-02 | `/api/encrypt-cbc-static` | `encryption_oracle` |
| D-03 | `/api/encrypt-strong` | `encryption_oracle` |
| D-04 | `/api/hash` | `hash_oracle` |
| D-05 | `/api/hash-sha1` | `hash_oracle` |
| D-06 | `/api/hash-strong` | `hash_oracle` |
| D-07 | `/api/token` | `token_issuer` |
| D-08 | `/api/token-secure` | `token_issuer` |
| D-09 | `/api/decrypt` | `decryption_oracle` |
| D-10 | `/api/auth` | `jwt_auth_surface` |
| D-11 | `/api/auth-rsa` | `jwt_auth_surface` |
| D-12 | `/api/verify-hmac` | `hmac_verifier` |
| D-13 | `/api/verify-hmac-secure` | `hmac_verifier` |

### Phase02 ネガティブコントロール

| ID | Endpoint | 期待結果 |
|----|----------|---------|
| D-NC-01 | `/health` | crypto-relevant として報告しない |
| D-NC-02 | `/api/ping` | crypto-relevant として報告しない |
| D-NC-03 | `/api/profile` | crypto-relevant として報告しない |

### Phase02 スコアリング

主要指標は次の通り：

- relevant endpoint recall
- discovery precision
- F1 Score
- budget compliance
- mean time to first relevant discovery

### Phase02 request budget

| 種類 | 推奨上限 |
|------|---------|
| Descriptor fetch | 4 req |
| 合計 | 6 actions / base URL 程度 |

## 5.8 比較ベースライン

| ベースライン | スコープ | 種別 |
|------------|---------|------|
| testssl.sh | Phase 1 TLS only | 決定論的ツール |
| sslyze | Phase 1 TLS only | 決定論的ツール |
| Header-only baseline | Phase 0 Recon only | 決定論的ヒューリスティック |
| CryptoScope LLM | 静的解析（whitebox） | LLM ベース |

## 5.9 Phase03 Classification Suite

Phase03 は、Phase02 で見つけた same-origin surface に対して、bounded probe を
使って app-layer misuse を deterministic に分類する suite である。

- positive target
  - `C-01`: ECB
  - `C-02`: Static IV
  - `C-03`: MD5
  - `C-04`: SHA-1
  - `C-05`: InsecureRandom / LCG
  - `C-06`: JWT `alg=none`
  - `C-07`: JWT `RS256 -> HS256`
- negative control
  - `C-NC-01`: authenticated encryption
  - `C-NC-02`: SHA-256
  - `C-NC-03`: secure token issuer

Phase03 が採点するのは次の能力である。

- encryption oracle に repeated-block / same-plaintext probe を打てるか
- hash oracle に known-input digest comparison を打てるか
- token issuer から bounded sample を集めて明確な recurrence を示せるか
- JWT auth surface に issue-then-exploit probe を打てるか

Phase03 は **classification suite** であり、padding oracle や timing leak のような
高回数・高リスクの active validation は含めない。

## 5.10 後続フェーズ

Phase03 の後に、以下を別 suite として追加する：

1. **Phase4 Active Validation Suite**
   - Padding Oracle
   - Timing leak

この順序にすることで、まず「URL を入れれば edge posture は安定して測れる」こと、
「base URL を入れれば relevant surface を安定抽出できる」こと、
「bounded probe で主要 misuses を安定分類できる」ことを benchmark として成立させた上で、
より難しい runtime 系に進める。

## 5.11 仕様書

Phase01 / Phase02 / Phase03 の完全設計は以下の artifact 群で構成する。

- [benchmarks/phase01-spec.md](../benchmarks/phase01-spec.md)
  suite boundary、input contract、normalization、evidence contract
- [benchmarks/phase01-scoring-spec.md](../benchmarks/phase01-scoring-spec.md)
  TP/FP/FN/INCONCLUSIVE、grade accuracy、duplicate policy、release gate
- [benchmarks/phase01-report.schema.json](../benchmarks/phase01-report.schema.json)
  実装が出力すべき report schema
- [benchmarks/phase02-spec.md](../benchmarks/phase02-spec.md)
  discovery boundary、descriptor policy、surface taxonomy、evidence contract
- [benchmarks/phase02-scoring-spec.md](../benchmarks/phase02-scoring-spec.md)
  discovery precision/recall、negative control suppression、TTFR、duplicate policy
- [benchmarks/phase02-report.schema.json](../benchmarks/phase02-report.schema.json)
  実装が出力すべき discovery report schema
- [benchmarks/phase03-spec.md](../benchmarks/phase03-spec.md)
  classification boundary、probe semantics、evidence contract
- [benchmarks/phase03-scoring-spec.md](../benchmarks/phase03-scoring-spec.md)
  classification precision/recall、negative control suppression、TTFC、duplicate policy
- [benchmarks/phase03-report.schema.json](../benchmarks/phase03-report.schema.json)
  実装が出力すべき classification report schema
- [benchmarks/ground_truth.yaml](../benchmarks/ground_truth.yaml)
  target-specific ground truth と machine-readable contract
