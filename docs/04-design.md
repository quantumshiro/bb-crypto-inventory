# 4. ブラックボックス暗号インベントリツール設計

## 4.1 設計思想

既存SOTAはほぼ全てホワイトボックス（ソースコードアクセス前提）。本設計では **エンドポイントURLのみ** を入力とし、外部から観測可能な情報だけで暗号インベントリを構築する。

LLMエージェントが複数の観測チャネルをオーケストレーションし、反復的に仮説を精緻化する。

```
入力: https://target.example.com
  ↓
┌──────────────────────────────────────┐
│       LLM Agent (Orchestrator)        │
│     Plan → Act → Observe ループ      │
│                                      │
│  仮説生成 → ツール実行 → 結果解釈    │
│  → 仮説更新 → 追加テスト → 収束     │
└──────────────────────────────────────┘
  ↓
出力: CBOM (CycloneDX JSON) + 脆弱性レポート + 確信度スコア
```

## 4.2 6つの観測チャネル

ブラックボックスから暗号情報を取得するための6つの独立した観測チャネル：

| チャネル | 略称 | 観測対象 | 取得情報 |
|---------|------|---------|---------|
| CH1 | TLSハンドシェイク | TLS ClientHello/ServerHello | 暗号スイート、証明書、TLSバージョン、PFS |
| CH2 | 暗号文統計解析 | API応答の暗号文 | ECBパターン、静的IV、ブロックサイズ、パディング方式 |
| CH3 | エラー差分解析 | 異常入力への応答差分 | Padding Oracle、Bleichenbacher |
| CH4 | タイミングサイドチャネル | 応答時間の統計分布 | 定数時間実装の有無、タイミングリーク |
| CH5 | ハッシュ/署名構造 | API応答中のハッシュ・署名・トークン | アルゴリズム推定、JWT解析、alg confusion |
| CH6 | 乱数品質 | セッションID・トークンの統計性質 | NIST SP 800-22統計テスト |

### チャネル間の相互検証

複数チャネルからの証拠が一致する場合、確信度を引き上げる。例：

- CH1（TLS）でCBC暗号スイート検出 + CH3（エラー差分）でPadding Oracle検出 → 確信度1.0
- CH2（暗号文統計）でブロックサイズ16推定 + CH5（ハッシュ長）でAES推定 → 確信度上昇

## 4.3 アーキテクチャ: Plan-Act-Observe ループ

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│   Plan   │────→│   Act    │────→│ Observe  │
│          │     │          │     │          │
│ LLMが次の│     │ ツールを │     │ 結果を   │
│ テスト計画│     │ Function │     │ 解釈し   │
│ を立案   │     │ Calling  │     │ 仮説更新 │
│          │     │ で実行   │     │          │
└──────────┘     └──────────┘     └──────────┘
     ↑                                  │
     └──────────────────────────────────┘
              未検証仮説がある限り反復
```

### 収束条件
1. 全観測チャネルのテストが完了し、未検証の仮説がない
2. または最大反復回数（デフォルト5回）に到達
3. またはタイムアウト（デフォルト30分）

## 4.4 4フェーズの実行計画

### Phase 0: 偵察（Recon）

対象エンドポイントの基本情報を収集し、以降のフェーズのテスト計画を立案する。

| ツール | 内容 |
|--------|------|
| `nmap_scan` | ポートスキャン。443, 22, 8443, 993等の暗号化ポートを優先 |
| `fetch_http_headers` | HTTP応答ヘッダ。Server, X-Powered-Byからミドルウェア推定。HSTS確認 |
| `fetch_certificate_chain` | 証明書チェーン。署名アルゴリズム、鍵長、CA、有効期限、SAN |
| `probe_openapi_spec` | OpenAPI仕様取得。/swagger.json, /openapi.json等をプローブ |

**LLMの役割**: Recon結果を解釈し、「このサーバはJava/Spring BootでOpenSSL系。TLS 1.2とTLS 1.3両方対応」のような仮説を生成。以降のテスト計画を自動設計。

### Phase 1: プロトコル層テスト

TLS/SSH等のプロトコル層で使用されている暗号を完全に列挙する。

**TLSプロービング:**
| ツール | 内容 |
|--------|------|
| `enumerate_cipher_suites` | 全既知スイートを含むClientHelloを送信し、受入スイートを全列挙 |
| `test_protocol_versions` | TLS 1.0/1.1/1.2/1.3の各バージョンで接続試行 |
| `test_downgrade_attack` | TLS_FALLBACK_SCSV対応確認 |
| `test_pqc_support` | ML-KEM(Kyber)ハイブリッド鍵交換（X25519Kyber768）の受入確認 |

**SSHプロービング:**
| ツール | 内容 |
|--------|------|
| `ssh_probe` | 鍵交換、ホスト鍵、暗号化、MACアルゴリズムの列挙 |

**TLSスコアリング**: Qualys SSL Labs Rating Guide v2009rに準拠。Protocol (30%) + Key Exchange (30%) + Cipher Strength (40%)。

### Phase 2: アプリケーション層テスト

アプリケーションが内部で使用している暗号を推定する。

**CH2: 暗号文構造解析**
| テスト | 手法 | 検出精度 |
|--------|------|---------|
| ECBモード検出 | 同一平文の繰り返し送信、暗号文内の同一ブロック検出 | 理論上100% |
| 静的IV検出 | 同一平文の複数回暗号化、出力の同一性確認 | 高 |
| パディング方式推定 | 入力長変化 vs 出力長変化のプロット | 中-高 |
| ブロックサイズ推定 | 出力長の変化パターン（16B→AES, 8B→3DES/Blowfish） | 高 |

**CH5: ハッシュ/署名/トークン解析**
| テスト | 手法 |
|--------|------|
| JWT解析 | Bearerトークンのalgフィールド確認 |
| alg confusion | alg=none, RS256→HS256切替テスト |
| ハッシュ長分析 | 128bit=MD5, 160bit=SHA-1, 256bit=SHA-256 |
| 署名長分析 | 256bytes=RSA-2048, 512bytes=RSA-4096 |

**CH6: 乱数品質テスト（少数サンプル Tier 方式）**

ブラックボックス評価では大量リクエストによるWAF/BAN リスクを回避するため、**50〜500 サンプル** の範囲で段階的に評価する Tier 方式を採用する（詳細: [07-small-sample-randomness.md](07-small-sample-randomness.md)）。

| Tier | 必要サンプル数 | テスト | 検出対象 |
|------|--------------|--------|---------|
| Tier 1 | 50〜100 | 差分解析 | 連番ID、タイムスタンプベース、LCG下位ビット周期性 |
| Tier 1 | 50〜100 | Permutation Entropy (Bandt & Pompe 2002) | 時系列的パターン、非線形依存性 |
| Tier 2 | 100〜500 | SHR エントロピー推定 (Hausser & Strimmer 2009) | バイト分布の偏り（少数サンプルで最小バイアス） |
| Tier 2 | 100〜500 | Anderson-Darling 一様性検定 | 分布のテール偏り（KS検定より高検出力） |
| Tier 2 | 100〜500 | χ²バイト頻度検定 | バイト値の頻度偏り |
| Tier 2 | 100〜500 | Collision Test | 乱数空間の狭さ（弱いPRNG、短いシード） |
| Tier 3 | 500〜2000 | SPRT 逐次検定 (Wald 1945) | 逐次的にランダム性を判定、早期終了対応 |
| Tier 3 | 500〜2000 | Min-Entropy 推定 (SP 800-90B) | min-entropy 下界推定（MCV, Collision, Lag Predictor） |
| Tier 3 | 500〜2000 | Maurer's Universal Test (Maurer 1992) | 圧縮可能パターンによるエントロピーレート測定 |

**早期終了メカニズム**: Tier 1 で連番等の明白な欠陥が検出された場合、追加サンプル収集せず即座にレポートする。SPRT（逐次確率比検定）により、判定に十分な確信度が得られた時点でサンプル収集を停止する。

**旧方式（NIST SP 800-22）からの変更理由**:
- SP 800-22 は数万サンプル前提であり、ブラックボックス評価では WAF/BAN リスクが高い
- SP 800-22 のテスト間の独立性不足や Type II エラーの問題が指摘されている (ePrint 2022/169)
- 新方式は 50〜500 サンプルで実用的な検出力を達成する

### Phase 3: Oracle・タイミング解析

暗号実装の深層の脆弱性を検出する。

**CH3: Padding Oracle検出**
1. Phase 2で推定したCBCモード暗号文を取得
2. 最終ブロックの最後の1バイトを0x00～0xFFで変更した256リクエスト送信
3. 応答をクラスタリング（「パディング不正」vs「復号成功だが内容不正」）
4. 2種類以上の応答パターンがあればPadding Oracle存在
5. HTTPステータスコード差分、エラーメッセージ差分、タイミング差分の3つで確認

**CH4: タイミング解析**
| テスト | 手法 |
|--------|------|
| HMAC検証タイミング | 正しいMACの先頭Nバイト一致を増やしながら応答時間測定。各N=5000回以上 |
| 定数時間実装確認 | 入力を系統的に変えて応答時間の分散を測定 |
| ノイズ低減 | 中央値ベース統計、外れ値除去、ブートストラップ検定 |

## 4.5 LLMエージェントのTool定義

LLMエージェントがFunction Callingで呼び出すTool一覧：

| Tool | Phase | 説明 |
|------|-------|------|
| `nmap_scan(host, ports)` | 0 | ポートスキャンとサービス特定 |
| `fetch_http_headers(url)` | 0 | HTTP応答ヘッダ取得 |
| `fetch_certificate_chain(host, port)` | 0 | 証明書チェーン取得・解析 |
| `probe_openapi_spec(base_url)` | 0 | OpenAPI仕様発見 |
| `enumerate_cipher_suites(host, port)` | 1 | TLS暗号スイート全列挙 |
| `test_protocol_versions(host, port)` | 1 | TLSバージョン対応確認 |
| `test_downgrade_attack(host, port)` | 1 | ダウングレード耐性テスト |
| `test_pqc_support(host, port)` | 1 | PQC対応確認 |
| `ssh_probe(host, port)` | 1 | SSH暗号列挙 |
| `collect_tokens(url, n)` | 2 | セッションID/トークン収集（デフォルト N=200） |
| `analyze_jwt(token)` | 2 | JWTヘッダ・ペイロード解析 |
| `send_and_compare_ciphertext(url, payload, n)` | 2 | 暗号文比較 |
| `randomness_test(samples, max_tier, early_stop)` | 2 | Tier 1-3 統合乱数品質テスト（少数サンプル対応） |
| `analyze_hash_length(hash_values)` | 2 | ハッシュ長分析 |
| `padding_oracle_test(url, ciphertext)` | 3 | Padding Oracle検証 |
| `timing_analysis(url, payloads, n)` | 3 | タイミング差分測定 |
| `report_finding(category, severity, ...)` | 全 | 検出結果をCBOMに記録 |

## 4.6 検出可能カテゴリと限界

### 検出可能（ブラックボックス）
| カテゴリ | 検出チャネル | 根拠 |
|---------|------------|------|
| ECBMode | CH2 | 同一ブロック→同一暗号文（決定的） |
| StaticIV | CH2 | 同一平文→同一暗号文（決定的） |
| WeakHash (MD5/SHA-1) | CH5 | 出力長から特定（決定的） |
| InsecureRandom | CH6 | Tier 1-3 少数サンプル統計テストで検出 |
| PaddingOracle | CH3 | エラー差分（確率的） |
| InsecureCipherSuite | CH1 | TLS列挙（決定的） |
| NoPFS | CH1 | 静的RSA鍵交換の受入確認 |
| JWTAlgConfusion | CH5 | alg切替テスト |
| TimingLeak | CH4 | 統計的タイミング差分 |

### 検出困難（ブラックボックスの原理的限界）
| カテゴリ | 理由 | 補完手段 |
|---------|------|---------|
| HardcodedKey | 内部状態。外部から観測不能 | SBOM/メタデータからの間接推論 |
| InsecureKeyDerivation | 鍵導出の実装詳細。外部信号なし | ソースコード解析との併用 |
| InsecureKeyStorage | サーバ側ストレージ。外部信号なし | ホストスキャンとの併用 |

## 4.7 出力形式

最終出力は **CycloneDX CBOM形式（JSON）**。各暗号資産に以下を付与：

```json
{
  "algorithm": "検出された暗号アルゴリズム名",
  "key_length": 2048,
  "key_length_estimated": true,
  "pq_vulnerable": true,
  "detection_channel": "CH1:TLS_HANDSHAKE",
  "confidence": 0.95,
  "evidence": { "raw_data": "..." },
  "remediation": "ML-KEM ハイブリッド鍵交換への移行を推奨"
}
```

## 4.8 現実的な課題と対策

| 課題 | 対策 |
|------|------|
| 誤検出 (False Positive) | 確信度スコアで「確定」と「推定」を区別。複数チャネルで裏付けされた場合のみ確信度を上げる |
| ネットワークジッタ | タイミング解析で数千回測定 + 中央値ベース + ブートストラップ検定。ローカルエージェント配置オプションも提供 |
| WAF/レートリミット | 少数サンプル Tier 方式（N≤500）でリクエスト数を大幅削減。CH1-CH5 は数十リクエスト、CH6 も最大500リクエストで評価完了。早期終了により最小 50 リクエストで判定可能 |
| API仕様不明 | LLMがまずCrawl/Fuzzでエンドポイント発見 → 暗号関連をフィルタ |
| ブラックボックスの原理的限界 | HardcodedKey等は検出不能。SBOM/メタデータからの間接推論で補完 |

## 4.9 MVP計画

| フェーズ | スコープ | 期間 |
|---------|---------|------|
| MVP | Phase 0+1（偵察 + TLSプロービング） | 2-3ヶ月 |
| v1.0 | Phase 0-3（全フェーズ） | 6-12ヶ月 |

ブラックボックスベンチマーク作成自体が学術貢献。
