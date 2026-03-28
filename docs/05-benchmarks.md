# 5. ベンチマーク設計

## 5.1 背景と新規性

暗号誤用検出のベンチマークとして、CamBench (MSR 2022) や CryptoAPI-Bench (IEEE SecDev 2019) が確立されているが、これらは全て **ホワイトボックス/静的解析** 向けである。

**ブラックボックス暗号インベントリの標準ベンチマークは学術上存在しない。** 本ベンチマークスイートはこのギャップを埋め、以下を提供する：

1. CamBench/CryptoAPI-Benchの脆弱性分類体系をブラックボックス観測に適応
2. 意図的に脆弱な暗号を実装したテストサーバ群
3. グラウンドトゥルース付きの定量評価基盤

## 5.2 準拠するスタンダード

### 脆弱性分類
| 本ベンチマーク | CamBench Rule | CryptoAPI-Bench Rule | MASC Operator | CWE |
|--------------|---------------|---------------------|---------------|-----|
| ECBMode | Rule 3 | Rule 3 | M76 | CWE-327 |
| StaticIV | Rule 4 | — | M69 | CWE-329 |
| WeakHash | Rule 16 | Rule 16 | M86 | CWE-328 |
| InsecureRandom | Rule 14 | Rule 14 | M74 | CWE-330 |
| PaddingOracle | N/A (runtime) | N/A | N/A | CWE-209, CWE-649 |
| InsecureCipherSuite | Rule 1 | Rule 1 | M89 | CWE-326, CWE-327 |
| NoPFS | N/A (TLS config) | N/A | N/A | CWE-320 |
| WeakProtocolVersion | N/A (TLS config) | N/A | N/A | CWE-326 |
| JWTAlgConfusion | N/A (JWT) | N/A | N/A | CWE-347 |
| TimingLeak | N/A (runtime) | N/A | N/A | CWE-208 |

### TLSスコアリング
**Qualys SSL Labs Rating Guide v2009r** に準拠：

```
総合スコア = Protocol(30%) + Key Exchange(30%) + Cipher Strength(40%)
```

| プロトコル | スコア |
|-----------|--------|
| SSLv2 | 0% |
| SSLv3 | 80% |
| TLSv1.0 | 90% |
| TLSv1.1 | 95% |
| TLSv1.2 | 100% |
| TLSv1.3 | 100% |

グレードキャップ：
- SSLv2 → F
- RC4 → max C
- 3DES (64-bit block) → max C
- No PFS → max B
- TLS 1.0/1.1 → max B

### テスト手法
**OWASP Web Security Testing Guide (WSTG) v4.2** Chapter 9 に対応：
- WSTG-CRYP-01: Testing for Weak TLS/SSL Ciphers
- WSTG-CRYP-02: Testing for Padding Oracle
- WSTG-CRYP-04: Testing for Weak Encryption

### 乱数テスト
**NIST SP 800-22 Rev 1a** の統計テスト：
- 周波数（モノビット）テスト
- ランテスト
- バイト頻度（カイ二乗）テスト
- 連続相関テスト

## 5.3 ベンチマークターゲット一覧

### 脆弱性ターゲット（10種）

| ID | 脆弱性 | チャネル | 期待確信度 | 検出方法 |
|----|--------|---------|-----------|---------|
| BM-01 | ECBモード (AES-128-ECB) | CH2 | ~1.0 | 同一ブロック繰り返し検出 |
| BM-02 | 静的IV (AES-128-CBC) | CH2 | High | 同一平文の暗号文一致検出 |
| BM-03 | 弱いハッシュ (MD5) | CH5 | High | 出力長32hex = 128bit |
| BM-04 | 弱いハッシュ (SHA-1) | CH5 | High | 出力長40hex = 160bit |
| BM-05 | 安全でない乱数 (LCG) | CH6 | Medium-High | NIST SP 800-22テスト不合格 |
| BM-06 | Padding Oracle | CH3 | High | エラー応答パターンの差分 |
| BM-07 | JWT alg=none | CH5 | ~1.0 | alg=none JWTの受入確認 |
| BM-08 | JWT RS256→HS256 | CH5 | High | アルゴリズム切替テスト |
| BM-09 | 弱いTLS設定 | CH1 | ~1.0 | SSL Labs方式スコアリング |
| BM-10 | タイミングリーク | CH4 | Medium | 統計的タイミング差分検出 |

### ネガティブコントロール（4種）

| ID | 内容 | 期待結果 |
|----|------|---------|
| NC-01 | AES-256-GCM（ランダムnonce） | 検出なし |
| NC-02 | SHA-256 | WeakHash検出なし |
| NC-03 | os.urandom()トークン | InsecureRandom検出なし |
| NC-04 | TLS 1.3 only + AEAD + HSTS | TLS関連検出なし（Grade: A+） |

## 5.4 スコアリング手法

CamBench / CryptoAPI-Bench の評価で標準的に使用されるIR指標：

| 指標 | 定義 | 説明 |
|------|------|------|
| Precision | TP / (TP + FP) | 報告された検出結果のうち正しいものの割合 |
| Recall | TP / (TP + FN) | グラウンドトゥルースの脆弱性のうち検出されたものの割合 |
| F1 Score | 2·P·R / (P+R) | Precision と Recall の調和平均 |
| Confidence Calibration | — | 報告された確信度と実際の正解率の整合性 |
| SSL Labs Grade Accuracy | — | TLSベンチマークの計算グレードと期待グレードの一致 |
| Detection Latency | — | 脆弱性クラスごとの初回検出までの時間 |

## 5.5 比較ベースライン

| ベースライン | スコープ | 種別 | 参考 |
|------------|---------|------|------|
| testssl.sh | TLS/SSLのみ（Phase 1） | 決定論的ツール | https://testssl.sh |
| sslyze | TLS/SSLのみ（Phase 1） | 決定論的ツール | https://github.com/nabla-c0d3/sslyze |
| CryptoScope LLM | 静的解析（ホワイトボックス） | LLMベース | arXiv:2508.11599 |
| ランダムベースライン | 全フェーズ | ランダム分類器 | — |

## 5.6 インフラストラクチャ

```
Docker Compose で起動:
├── vuln-app (Flask)     — BM-01〜BM-08, BM-10 の脆弱エンドポイント
├── nginx-weak           — BM-09: TLS 1.0/1.1, RC4, no PFS
└── nginx-strong         — NC-04: TLS 1.3 only, AEAD, HSTS
```

```bash
# 起動
cd benchmarks/nginx && bash generate-certs.sh && cd ../..
docker compose -f benchmarks/docker-compose.yaml up -d

# サーバ検証
pytest benchmarks/test_servers.py -v

# ベンチマーク実行
python -m benchmarks.runner --target http://localhost:9000
```
