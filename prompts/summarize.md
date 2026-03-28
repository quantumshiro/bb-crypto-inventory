# 最終サマリー

ターゲット `{{TARGET}}` に対する全フェーズの分析結果を統合してください。

## これまでの全findings

```json
{{ALL_FINDINGS}}
```

## 統合分析してほしいこと

1. 全findingsを重複排除し、最終的な暗号資産リストを作成
2. 複数チャネルから検出された項目は確信度を引き上げ
3. PQC移行レディネスの総合評価
4. 修正優先順位（severity × confidence でランク付け）
5. CycloneDX CBOM形式での最終出力

## 出力

以下のJSON形式で出力してください：

```json
{
  "target": "{{TARGET}}",
  "summary": {
    "total_crypto_assets": 0,
    "pq_vulnerable_count": 0,
    "critical_findings": 0,
    "ssl_labs_grade": "B"
  },
  "findings": [ ... ],
  "remediation_priorities": [
    {
      "rank": 1,
      "finding": "...",
      "action": "..."
    }
  ],
  "pqc_readiness": {
    "score": "low|medium|high",
    "assessment": "..."
  }
}
```
