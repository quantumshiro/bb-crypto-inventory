# 7. 少数サンプルによる乱数品質評価手法

## 7.1 背景と動機

CH6（乱数品質テスト）の元設計（04-design.md）では NIST SP 800-22 Rev 1a に基づき、セッションID・トークンを **数千〜数万件** 収集して統計テストを実施する方針であった。しかしブラックボックス評価では以下の制約がある：

1. **WAF/レートリミット**: 同一エンドポイントへの大量リクエストは検知・BAN対象
2. **法的リスク**: 許諾なき第三者サイトへの大量アクセスは不正アクセス法に抵触しうる
3. **時間コスト**: スローペースモード（1 req/min）では数千件収集に数日かかる
4. **SP 800-22 自体の問題**: 大量サンプル前提の設計であり、少数サンプルでは Type II エラーが極めて高い

本章では、**50〜500 サンプル** の範囲で実用的な乱数品質評価を行うための統計手法を整理し、bbci の CH6 実装に採用する手法を選定する。

## 7.2 SP 800-22 の限界

Hurley-Smith & Hernandez-Castro (2022) は SP 800-22 テストスイートの根本的な問題を指摘している：

- テスト間の **統計的独立性が不十分** であり、冗長なテストが含まれる
- 参照分布が **ヒューリスティック近似** に依存しており、理論的に正確でないものがある（特にDFTテスト）
- 小サンプルでの検出力が著しく低く、**Type II エラー（見逃し）が多い**
- 代替として **圧縮ベース・エントロピー推定ベース** のアプローチを推奨

> **参考**: Hurley-Smith, D. & Hernandez-Castro, J. "SP 800-22 and GM/T 0005-2012 Tests: Clearly Obsolete, Possibly Harmful." *IACR ePrint* 2022/169.
> https://eprint.iacr.org/2022/169

## 7.3 採用する統計手法

### 7.3.1 Tier 1: 即座検出（N = 50〜100）

最小限のサンプルで「明らかにダメな」乱数実装を検出する。

#### (a) 差分解析によるパターン検出

連続するトークン間の差分を計算し、連番（インクリメンタルID）、タイムスタンプベース、線形合同生成器（LCG）の下位ビットパターンを検出する。

- **検出対象**: 連番ID、タイムスタンプ埋め込み、LCG（差分の周期性）
- **必要サンプル数**: 20〜50
- **理論的根拠**: LCG の出力列 $x_{n+1} = ax_n + c \mod m$ は、差分列 $d_n = x_{n+1} - x_n$ が有限周期を持つ

#### (b) Permutation Entropy（順列エントロピー）

時系列の順序パターンのみを使ってエントロピーを推定する。元は複雑系・カオスの分野で提案されたが、セッションIDの時系列的パターン検出に応用可能。

- **必要サンプル数**: 100〜数百
- **計算**: 埋め込み次元 $m$ のシンボル列に対し、$m!$ 通りの順列パターンの出現頻度からShannon エントロピーを計算
- **利点**: ノイズに対してロバスト、非線形パターンも検出可能

> **参考**: Bandt, C. & Pompe, B. "Permutation Entropy: A Natural Complexity Measure for Time Series." *Physical Review Letters*, 88(17), 2002.
> https://doi.org/10.1103/PhysRevLett.88.174102

### 7.3.2 Tier 2: 統計的検出（N = 100〜500）

中程度のサンプル数で統計的に有意な偏りを検出する。

#### (c) SHR エントロピー推定器（Shrinkage Estimator）

18 種類のエントロピー推定器の比較研究で、バイト列（アルファベットサイズ k=256）の短系列において **最もバイアスが小さく、MSE の収束が最速** であることが示された。

- **必要サンプル数**: n < k（アンダーサンプル領域）でも推定可能
- **計算**: 経験分布とターゲット分布（一様分布）を James-Stein 型の縮約で混合し、プラグインエントロピーを計算
- **バイト列でのバイアス**: 他推定器（MLE, Miller-Madow, Jackknife 等）と比較して最小

> **参考**: Marcon, E. et al. "Selecting an Effective Entropy Estimator for Short Sequences of Bits and Bytes with Maximum Entropy." *Entropy*, 23(5), 561, 2021.
> https://doi.org/10.3390/e23050561
> https://pmc.ncbi.nlm.nih.gov/articles/PMC8147137/

> **原論文**: Hausser, J. & Strimmer, K. "Entropy Inference and the James-Stein Estimator, with Application to Nonlinear Gene Association Networks." *Journal of Machine Learning Research*, 10, 2009.
> https://jmlr.org/papers/v10/hausser09a.html

#### (d) Anderson-Darling 検定

分布の一様性を検定する。Kolmogorov-Smirnov 検定より **分布の裾（テール）の偏りに敏感** であり、少ないサンプルで偏りを検出できる。

- **必要サンプル数**: 100〜数百
- **帰無仮説**: サンプルは一様分布 $U(0, 1)$ に従う（トークン値を正規化して適用）
- **利点**: KS 検定より検出力が高い（特に分布の両端の偏りに対して）

> **参考**: Anderson, T.W. & Darling, D.A. "A Test of Goodness of Fit." *Journal of the American Statistical Association*, 49(268), 1954.
> https://doi.org/10.1080/01621459.1954.10501232

> **実装参考**: D'Agostino, R.B. & Stephens, M.A. *Goodness-of-Fit Techniques.* Marcel Dekker, 1986.

#### (e) χ²（カイ二乗）検定

バイトレベルの頻度分布を一様分布と比較する。古典的だが少数サンプルでも実用的。

- **必要サンプル数**: 各バイト値の期待頻度 ≥ 5 が目安 → 256 × 5 = 1,280 バイト（セッションID 80〜100 個程度）
- **計算**: $\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i}$
- **判定**: 自由度 255、有意水準 0.01 で棄却域 $\chi^2 > 310.46$

#### (f) Collision Test（衝突テスト）

サンプル間の衝突（同一値の出現）を検出する。真にランダムなら誕生日のパラドックスに従う衝突率となる。

- **必要サンプル数**: 100〜数百
- **計算**: $N$ 個のサンプルで衝突数 $C$ を計測。期待衝突数 $E[C] = \frac{N(N-1)}{2 \cdot 2^b}$（$b$ はビット長）
- **検出対象**: 乱数空間が想定より小さい場合（弱い PRNG、短いシード）に衝突が過剰発生

### 7.3.3 Tier 3: 高精度評価（N = 200〜2,000、逐次収集）

時間をかけて追加収集しつつ、より精密な評価を行う。

#### (g) Wald の逐次確率比検定（SPRT）

サンプルを1個ずつ取りながら「ランダムか否か」を逐次的に判定する。固定サンプルの検定より **平均的に少ないサンプルで同じ検出力** を達成できる。

- **原理**: 各サンプル取得ごとに尤度比 $\Lambda_n = \prod_{i=1}^{n} \frac{f_1(x_i)}{f_0(x_i)}$ を更新
- **判定**: $\Lambda_n \geq B$ なら $H_1$（非ランダム）を採択、$\Lambda_n \leq A$ なら $H_0$（ランダム）を採択、$A < \Lambda_n < B$ なら追加サンプル取得
- **利点**: 明らかにダメな乱数は数十サンプルで早期棄却、問題ない乱数も早期に合格判定
- **応用**: 第二次世界大戦中の弾薬品質管理から発展。臨床試験の中間解析でも標準手法

> **参考**: Wald, A. "Sequential Tests of Statistical Hypotheses." *Annals of Mathematical Statistics*, 16(2), 117-186, 1945.
> https://doi.org/10.1214/aoms/1177731118

> **教科書**: Wald, A. *Sequential Analysis.* John Wiley & Sons, 1947. (Dover reprint 2004)

#### (h) NIST SP 800-90B Min-Entropy 推定

SP 800-22 の代わりに SP 800-90B のエントロピー推定器群を使用する。特に予測ベース推定器（MCW Predictor, MultiMMC Predictor, Lag Predictor）はサンプル列から min-entropy の下界を推定する。

- **必要サンプル数**: 1,000 推奨だが数百でも有意義な推定が可能
- **min-entropy**: $H_\infty = -\log_2(\max_x p(x))$。Shannon エントロピーの下界であり、暗号学的により保守的な評価
- **予測ベース推定**: 各推定器が次のサンプルを予測し、予測成功率から min-entropy を逆算

> **参考**: NIST SP 800-90B, "Recommendation for the Entropy Sources Used for Random Bit Generation", 2018.
> https://csrc.nist.gov/publications/detail/sp/800-90b/final

> **実装**: https://github.com/usnistgov/SP800-90B_EntropyAssessment

> **改良**: Kim, H. et al. "On the Efficient Estimation of Min-Entropy." *IEEE Trans. on Information Forensics and Security*, 16, 3013-3025, 2021.
> https://doi.org/10.1109/TIFS.2021.3070424

#### (i) Maurer's Universal Statistical Test

データの圧縮可能性を通じてエントロピーレートを直接測定する。SP 800-90B の Compression Estimator のベースとなった手法。

- **原理**: ブロック間の繰り返しパターンの距離を計測し、情報量を推定
- **利点**: 広範なクラスの統計的欠陥を単一のテストで検出可能（"universal"）
- **必要サンプル数**: パラメータ $L$（ブロック長）と $Q$（初期化長）に依存。$L=6, Q=640$ で実用的

> **参考**: Maurer, U.M. "A Universal Statistical Test for Random Bit Generators." *Journal of Cryptology*, 5(2), 89-105, 1992.
> https://doi.org/10.1007/BF00193563

> **精度改善**: Coron, J.-S. & Naccache, D. "An Accurate Evaluation of Maurer's Universal Test." *Selected Areas in Cryptography (SAC)*, Springer LNCS 1556, 1998.
> https://doi.org/10.1007/3-540-48892-8_5

### 7.3.4 補助手法: 臨床試験・品質管理からの借用

#### (j) ベイズ適応デザイン

事前分布を設定し、データが集まるごとに事後分布を更新して早期終了判定を行う。臨床試験では「できるだけ少ない被験者で効果を判定する」ための標準手法。

- **乱数品質への応用**: 事前分布「まともなフレームワークなら CSPRNG 使用」（弱い事前情報）を設定し、各サンプルで Bayes Factor を更新。閾値超過で判定
- **利点**: ドメイン知識（フレームワーク推定結果等）を事前分布に組み込める

> **参考**: Berry, D.A. "Bayesian Clinical Trials." *Nature Reviews Drug Discovery*, 5, 27-36, 2006.
> https://doi.org/10.1038/nrd1927

#### (k) TestU01 SmallCrush

L'Ecuyer & Simard の TestU01 スイートの最軽量バッテリー。**約 200 万ビット**（= セッションID 約 15,000〜20,000 個）でテスト可能だが、SP 800-22 フルスイートより検出力は同等以上。CH6 の上限設定として参考になる。

> **参考**: L'Ecuyer, P. & Simard, R. "TestU01: A C Library for Empirical Testing of Random Number Generators." *ACM Transactions on Mathematical Software*, 33(4), Article 22, 2007.
> https://doi.org/10.1145/1268776.1268777
> http://simul.iro.umontreal.ca/testu01/tu01.html

## 7.4 Tier 構成と実装方針

### 実行フロー

```
bbci scan https://target.example.com

CH6 実行フロー:
┌─────────────────────────────────────────────────────┐
│ Phase 1: Token Discovery                            │
│   - セッション/CSRF/リセットトークンのエンドポイント特定 │
│   - 複数エンドポイント分散で WAF リスク低減            │
└──────────────┬──────────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────────┐
│ Tier 1: 即座検出 (N=50-100)                         │
│   - 差分解析: 連番/タイムスタンプ/LCGパターン          │
│   - Permutation Entropy                             │
│   → 明らかな欠陥を検出したら即座にレポート             │
└──────────────┬──────────────────────────────────────┘
               ↓ (SPRT 逐次判定開始)
┌─────────────────────────────────────────────────────┐
│ Tier 2: 統計的検出 (N=100-500)                       │
│   - SHR Entropy Estimator                           │
│   - Anderson-Darling 一様性検定                      │
│   - χ² バイト頻度検定                                │
│   - Collision Test                                   │
│   → SPRT が判定に達したら早期終了                     │
└──────────────┬──────────────────────────────────────┘
               ↓ (判定未確定の場合のみ)
┌─────────────────────────────────────────────────────┐
│ Tier 3: 高精度評価 (N=500-2000, --deep モード)       │
│   - SP 800-90B Min-Entropy 推定                      │
│   - Maurer's Universal Test                          │
│   → 最終判定                                        │
└─────────────────────────────────────────────────────┘
```

### CLI インターフェース

```bash
# 標準スキャン: Tier 1 + Tier 2（N ≤ 500）
bbci scan https://target.example.com

# 高速モード: Tier 1 のみ（N ≤ 100）
bbci scan --fast https://target.example.com

# 深層モード: Tier 1 + 2 + 3（N ≤ 2000）
bbci scan --deep https://target.example.com

# サンプル数上限指定
bbci scan --max-tokens 200 https://target.example.com
```

### Tool 定義の更新

| Tool | 旧 | 新 |
|------|----|----|
| `collect_tokens(url, n)` | N=数千〜数万 | N=50〜500（デフォルト200） |
| `randomness_test(samples)` | SP 800-22 inspired | Tier 1-3 統合テスト |
| `randomness_test_tier1(samples)` | — | 新規: 差分解析 + Permutation Entropy |
| `randomness_test_tier2(samples)` | — | 新規: SHR + AD + χ² + Collision |
| `randomness_test_tier3(samples)` | — | 新規: SPRT + Min-Entropy + Maurer |

## 7.5 各手法の検出能力比較

| 欠陥タイプ | Tier 1 (N≤100) | Tier 2 (N≤500) | Tier 3 (N≤2000) |
|-----------|----------------|----------------|-----------------|
| 連番ID | ✅ 差分解析 | — | — |
| タイムスタンプベース | ✅ 差分解析 | — | — |
| LCG（線形合同法） | ✅ 差分解析 | ✅ χ² | ✅ Maurer |
| 短いシード/小さい状態空間 | — | ✅ Collision | ✅ Min-Entropy |
| 偏った分布 | ⚠️ PE（弱い） | ✅ AD + SHR | ✅ Min-Entropy |
| Mersenne Twister（非暗号PRNG） | — | ⚠️ 検出困難 | ⚠️ SmallCrush相当で一部検出 |
| CSPRNG（正常） | ✅ Pass | ✅ Pass | ✅ Pass |

⚠️ = 検出可能だが検出力が限定的

## 7.6 参考文献まとめ

| # | 著者 | タイトル | 出典 | URL |
|---|------|---------|------|-----|
| R1 | Hurley-Smith & Hernandez-Castro | SP 800-22 and GM/T 0005-2012 Tests: Clearly Obsolete, Possibly Harmful | IACR ePrint 2022/169 | https://eprint.iacr.org/2022/169 |
| R2 | Bandt & Pompe | Permutation Entropy: A Natural Complexity Measure for Time Series | Phys. Rev. Lett. 88(17), 2002 | https://doi.org/10.1103/PhysRevLett.88.174102 |
| R3 | Marcon et al. | Selecting an Effective Entropy Estimator for Short Sequences | Entropy 23(5), 2021 | https://doi.org/10.3390/e23050561 |
| R4 | Hausser & Strimmer | Entropy Inference and the James-Stein Estimator | JMLR 10, 2009 | https://jmlr.org/papers/v10/hausser09a.html |
| R5 | Anderson & Darling | A Test of Goodness of Fit | JASA 49(268), 1954 | https://doi.org/10.1080/01621459.1954.10501232 |
| R6 | Wald | Sequential Tests of Statistical Hypotheses | Ann. Math. Stat. 16(2), 1945 | https://doi.org/10.1214/aoms/1177731118 |
| R7 | NIST | SP 800-90B: Entropy Sources for Random Bit Generation | NIST, 2018 | https://csrc.nist.gov/pubs/sp/800/90/b/final |
| R8 | Kim et al. | On the Efficient Estimation of Min-Entropy | IEEE TIFS 16, 2021 | https://doi.org/10.1109/TIFS.2021.3070424 |
| R9 | Maurer | A Universal Statistical Test for Random Bit Generators | J. Cryptology 5(2), 1992 | https://doi.org/10.1007/BF00193563 |
| R10 | Coron & Naccache | An Accurate Evaluation of Maurer's Universal Test | SAC 1998 | https://doi.org/10.1007/3-540-48892-8_5 |
| R11 | Berry | Bayesian Clinical Trials | Nat. Rev. Drug Discov. 5, 2006 | https://doi.org/10.1038/nrd1927 |
| R12 | L'Ecuyer & Simard | TestU01: A C Library for Empirical Testing of RNGs | ACM TOMS 33(4), 2007 | https://doi.org/10.1145/1268776.1268777 |
| R13 | NIST | SP 800-22 Rev 1a: Statistical Test Suite for RNGs | NIST, 2010 | https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final |
