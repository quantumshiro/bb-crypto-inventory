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
    - 乱数品質評価の標準テストスイート。
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
