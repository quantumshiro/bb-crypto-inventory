# Phase 1: プロトコル層テスト（TLS/SSH）

ターゲット `{{TARGET}}` に対するTLS/SSHプロービングの結果です。

## ツール結果

```
{{TOOL_OUTPUT}}
```

## 分析してほしいこと

1. サポートされている暗号スイートを全て列挙し、弱いものを特定してください
2. TLSバージョン対応状況を確認し、古いバージョンが有効か報告してください
3. PFS（Forward Secrecy）が確保されているか評価してください
4. ダウングレード攻撃耐性（FALLBACK_SCSV）を確認してください
5. PQC対応（ML-KEM/Kyber）の有無を確認してください
6. SSH（ポート22）が開いていれば、弱いアルゴリズムを特定してください
7. SSL Labs Rating Guide v2009r に基づくグレードを推定してください
   - Protocol (30%) + Key Exchange (30%) + Cipher Strength (40%)
   - グレードキャップ: RC4→max C, No PFS→max B, TLS 1.0/1.1→max B

## 出力

system.md の報告フォーマットに従ってJSON形式で出力してください。
