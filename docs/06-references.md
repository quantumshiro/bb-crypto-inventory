# 6. 参考文献

## ロードマップ・ガイドライン

1. **CISA**, "Strategy for Automated PQC Discovery", 2024/08.
   - 米国CISAによるPQC自動発見戦略。Tychon ACDIを推奨。
   - https://www.cisa.gov/quantum

2. **AIVD/CWI/TNO**, "PQC Migration Handbook", 2024/12.
   - オランダ政府機関による実践的PQC移行ハンドブック。
   - クリプトインベントリ構築を第一ステップとして推奨。
   - https://english.aivd.nl/publications/publications/2023/04/04/the-pqc-migration-handbook

3. **PQCC (Post-Quantum Cryptography Coalition)**, "PQC Migration Roadmap", 2025/05.
   - 業界コンソーシアムによる移行ロードマップ。

## 静的解析・暗号検出

4. **Boehm et al.**, "Cryptoscope: Analyzing cryptographic usages in modern software", arXiv:2503.19531, 2025.
   - IBM Research。コンパイラ技術で暗号セマンティクスを構築。
   - CamBenchでSOTA（92%以上の捕捉率）。
   - https://arxiv.org/abs/2503.19531

5. **Hasan et al.**, "A Comprehensive Study on Post-Quantum Cryptography Migration", IEEE Access, 2024.
   - 被引用80件。依存グラフによるPQC移行順序最適化。
   - https://doi.org/10.1109/ACCESS.2024.XXXXXXX

## LLMによる暗号誤用検出

6. **CryptoScope LLM**, arXiv:2508.11599, 2025.
   - CoT + RAG、12K暗号知識ベース。GPT-4o-miniから20%改善。
   - 実世界コードベースから未知脆弱性9件発見。
   - https://arxiv.org/abs/2508.11599

7. **"Beyond Static Tools: Evaluating Large Language Models for Cryptographic Misuse Detection"**, arXiv:2411.09772, 2024.
   - LLM（GPT-4）が静的解析ツール（CryptoGuard、CogniCrypt、Snyk Code）を上回る。
   - プロンプトエンジニアリング後、F-measure 94.6%。
   - OWASP、CryptoAPI-Bench、MASCで評価。CamBenchで汎化確認。
   - https://arxiv.org/abs/2411.09772

8. **KG+LLM Framework**, arXiv:2601.03504, 2026.
   - ナレッジグラフ + LLM + Human-in-the-LoopでPQCレディネススコアリング。
   - https://arxiv.org/abs/2601.03504

## ベンチマーク

9. **Schlichtig et al.**, "CamBench — Cryptographic API Misuse Detection Tool Benchmark Suite", MSR 2022.
   - 暗号API誤用検出ツールの標準ベンチマーク。Java/JCA、静的解析向け。
   - CamBench_Real（実世界アプリ）+ CamBench_Cap（合成テスト）+ CamBench_Cov（カバレッジ）。
   - arXiv:2204.06447
   - https://github.com/CROSSINGTUD/CamBench

10. **Afrose et al.**, "CryptoAPI-Bench: A Comprehensive Benchmark on Java Cryptographic API Misuses", IEEE SecDev 2019.
    - 171テストケース、16誤用ルール。SpotBugs、CryptoGuard、CrySL、Coverityで評価。
    - https://github.com/CryptoAPI-Bench/CryptoAPI-Bench

11. **Ami et al.**, "Why Crypto-detectors Fail: A Systematic Evaluation of Cryptographic Misuse Detection Techniques" (MASC), USENIX Security 2022.
    - ミューテーションベースの暗号検出器評価。12一般化可能なミューテーション演算子。
    - arXiv:2107.07065
    - https://github.com/CryptoGuardOSS/MASC

12. **"ChatGPT's Potential in Cryptography Misuse Detection"**, ACM CCS Workshop 2024.
    - ChatGPTによるCryptoAPI-Bench、CamBench評価。
    - プロンプト最適化後、10カテゴリでSOTA超過。
    - https://dl.acm.org/doi/fullHtml/10.1145/3674805.3695408

## TLS/SSL評価

13. **Qualys SSL Labs**, "SSL Server Rating Guide", v2009r, 2025.
    - TLS設定評価のデファクトスタンダード。
    - Protocol Support (30%) + Key Exchange (30%) + Cipher Strength (40%)。
    - https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

14. **testssl.sh**
    - OSSのTLS/SSL検査ツール。SSL Labs Rating Guideのほぼ完全な実装。
    - https://testssl.sh

## OWASP

15. **OWASP**, "Web Security Testing Guide (WSTG) v4.2", Chapter 9: Testing for Weak Cryptography.
    - WSTG-CRYP-01: Testing for Weak TLS/SSL Ciphers, Insufficient Transport Layer Protection
    - WSTG-CRYP-02: Testing for Padding Oracle
    - WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels
    - WSTG-CRYP-04: Testing for Weak Encryption
    - https://owasp.org/www-project-web-security-testing-guide/

16. **OWASP Top 10:2025**, "A04: Cryptographic Failures".
    - 暗号の欠陥・不適切な使用が2025年版でも上位にランク。
    - CWE-259, CWE-327, CWE-331が主要CWE。
    - https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/

## 暗号標準・規格

17. **NIST SP 800-22 Rev 1a**, "A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications", 2010.
    - 乱数品質評価の標準テストスイート。**本プロジェクトでは不採用**（下記 25-32 の少数サンプル手法を代替採用）。
    - https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final

18. **NIST FIPS 203**, "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)", 2024.
    - ポスト量子鍵カプセル化標準（旧Kyber）。
    - https://csrc.nist.gov/publications/detail/fips/203/final

19. **NIST FIPS 204**, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", 2024.
    - ポスト量子デジタル署名標準（旧Dilithium）。
    - https://csrc.nist.gov/publications/detail/fips/204/final

20. **CycloneDX**, "Cryptographic Bill of Materials (CBOM) Specification", v1.6.
    - 暗号資産のインベントリ標準形式。
    - https://cyclonedx.org/capabilities/cbom/

## 古典的攻撃手法

21. **Vaudenay**, "Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS...", EUROCRYPT 2002.
    - Padding Oracle攻撃の原論文。

22. **Bleichenbacher**, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1", CRYPTO 1998.
    - RSA PKCS#1 v1.5に対するOracle攻撃。

23. **Crosby et al.**, "Opportunities and Limits of Remote Timing Attacks", ACM Transactions on Information and System Security, 2009.
    - リモートタイミング攻撃の実現可能性と限界。

24. **Auth0**, "Critical vulnerabilities in JSON Web Token libraries", 2015.
    - JWT alg=none, RS256→HS256 confusion等のJWT脆弱性。

## 少数サンプル乱数品質評価（CH6 Tier 方式）

25. **Hurley-Smith, D. & Hernandez-Castro, J.**, "SP 800-22 and GM/T 0005-2012 Tests: Clearly Obsolete, Possibly Harmful", IACR ePrint 2022/169, 2022.
    - SP 800-22 の根本的問題を指摘。代替手法の必要性を論じる。
    - https://eprint.iacr.org/2022/169

26. **Bandt, C. & Pompe, B.**, "Permutation Entropy: A Natural Complexity Measure for Time Series", Physical Review Letters, 88(17), 2002.
    - 順列エントロピー。少数サンプルの時系列パターン検出に使用（Tier 1）。
    - https://doi.org/10.1103/PhysRevLett.88.174102

27. **Hausser, J. & Strimmer, K.**, "Entropy Inference and the James-Stein Estimator, with Application to Nonlinear Gene Association Networks", JMLR 10, 2009.
    - SHR（Shrinkage）エントロピー推定器。少数サンプルで最小バイアス（Tier 2）。
    - https://jmlr.org/papers/v10/hausser09a.html

28. **Marcon, E. et al.**, "Selecting an Effective Entropy Estimator for Short Sequences of Bits and Bytes with Maximum Entropy", Entropy 23(5), 561, 2021.
    - 18種のエントロピー推定器を比較。SHR が短バイト列で最良と結論。
    - https://doi.org/10.3390/e23050561

29. **Wald, A.**, "Sequential Tests of Statistical Hypotheses", Annals of Mathematical Statistics, 16(2), 117-186, 1945.
    - 逐次確率比検定（SPRT）。固定サンプルより少ない観測数で同等の検出力（Tier 3）。
    - https://doi.org/10.1214/aoms/1177731118

30. **NIST SP 800-90B**, "Recommendation for the Entropy Sources Used for Random Bit Generation", 2018.
    - Min-Entropy 推定手法。MCV, Collision, 予測ベース推定器を採用（Tier 3）。
    - https://csrc.nist.gov/pubs/sp/800/90/b/final

31. **Maurer, U.M.**, "A Universal Statistical Test for Random Bit Generators", Journal of Cryptology, 5(2), 89-105, 1992.
    - 圧縮可能性によるエントロピーレート測定。広範な統計的欠陥を単一テストで検出（Tier 3）。
    - https://doi.org/10.1007/BF00193563

32. **Anderson, T.W. & Darling, D.A.**, "A Test of Goodness of Fit", JASA, 49(268), 1954.
    - 分布の一様性検定。KS検定よりテール偏りに対して高感度（Tier 2）。
    - https://doi.org/10.1080/01621459.1954.10501232

33. **L'Ecuyer, P. & Simard, R.**, "TestU01: A C Library for Empirical Testing of Random Number Generators", ACM TOMS, 33(4), 2007.
    - SmallCrush バッテリー。SP 800-22 より少ないデータ量で同等以上の検出力。設計時の比較参考。
    - https://doi.org/10.1145/1268776.1268777

34. **Kim, H. et al.**, "On the Efficient Estimation of Min-Entropy", IEEE Trans. Information Forensics and Security, 16, 2021.
    - Maurer テストベースの改良 min-entropy 推定器。計算量と推定精度の改善。
    - https://doi.org/10.1109/TIFS.2021.3070424
