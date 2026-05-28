# CRYSTALS-Kyber Implementation (Python)

NIST標準耐量子暗号 **CRYSTALS-Kyber (ML-KEM)** の Python スクラッチ実装です。  
卒業論文「格子暗号に基づく公開鍵暗号方式 CRYSTALS-Kyber の実装」より。

---

## 概要

量子計算機による攻撃への耐性を持つ格子暗号ベースの鍵カプセル化機構 (KEM) を  
仕様書に基づきゼロから実装しました。

| レイヤー | 内容 |
|---|---|
| CPAPKE | IND-CPA安全な公開鍵暗号（鍵生成・暗号化・復号） |
| CCAKEM | Fujisaki-Okamoto変換によるIND-CCA安全なKEM |

---

## 実装内容

### アルゴリズム
- **鍵生成**：Module-LWEに基づく公開鍵・秘密鍵の生成
- **暗号化**：NTT高速多項式乗算を用いた暗号文生成
- **復号**：暗号文検証と暗黙的リジェクション（fallback key）
- **NTT**：バタフライ演算による数論変換・逆変換
- **ハッシュ**：G / H / KDF / XOF (SHA3系)
- **サンプリング**：中心化二項分布 CBD によるノイズ生成

### パラメータセット
| パラメータ | k | 安全レベル |
|---|---|---|
| Kyber512 | 2 | Level 1 (AES-128相当) |
| Kyber768 | 3 | Level 3 (AES-192相当) |
| Kyber1024 | 4 | Level 5 (AES-256相当) |

### ディレクトリ構成
| パス | 内容 |
|---|---|
| `Kyber/kem/` | CCAKEM・KeyGen・Enc・Dec |
| `Kyber/utils/` | NTT・Hash・CBD・Encode・Compress・Parse |
| `Kyber/parameters/` | Kyber512 / Kyber768 / Kyber1024 パラメータ |
| `Kyber/tests/` | pytest テストスイート |
| `run_tests.py` | テスト実行スクリプト |


## テスト

```bash
python run_tests.py
```

以下の項目を検証しています。

- NTT変換の往復一致
- NTT多項式積とナイーブ計算の一致
- バイト列シリアライズ・デシリアライズの往復
- CPAPKE 鍵生成→暗号化→復号の整合性
- CCAKEM Encaps/Decaps による共有鍵一致
- 全パラメータセットで5,000試行・復号失敗ゼロ

---

## 使用技術

- Python 3.11+
- pytest
