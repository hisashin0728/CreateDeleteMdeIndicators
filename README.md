# Upload-MDEIndicators

FileSha1 / FileSha256 / FileMd5 / IpAddress / DomainName / Url を Microsoft Defender for Endpoint のカスタムインジケーターに一括登録する PowerShell スクリプトです。

## 前提条件

### Azure AD アプリ登録

1. Azure Portal → **アプリの登録** で新規登録
2. **API のアクセス許可** → **API の追加** → **所属する組織で使用している API** → **WindowsDefenderATP** → アプリケーションの許可:
   - `Ti.ReadWrite.All` (インジケーターの読み取り/書き込み)
3. **管理者の同意を付与** をクリック
4. **証明書とシークレット** → クライアントシークレットを作成

## CSV フォーマット

| 列名 | 必須 | 説明 |
|------|------|------|
| IndicatorValue | ○ | インジケーター値 (ハッシュ / IP / ドメイン / URL) |
| IndicatorType | | `FileSha1` / `FileSha256` / `FileMd5` / `IpAddress` / `DomainName` / `Url` (省略時は自動判定) |
| Title | | インジケーターのタイトル |
| Description | | 説明 |
| Severity | | `Informational` / `Low` / `Medium` / `High` |
| Action | | `AlertAndBlock` / `Alert` / `Allowed` / `Block` / `Audit` |
| ExpirationTime | | 有効期限 (ISO 8601 形式: `2026-12-31T00:00:00Z`) |
| RecommendedActions | | 推奨アクション |

> **後方互換性**: 旧フォーマットの `Sha1` 列のみの CSV もそのまま使用できます。

### IndicatorType 自動判定ルール

| パターン | 判定結果 |
|---------|---------|
| `http://` または `https://` で始まる | Url |
| IPv4 形式 (`x.x.x.x`) / IPv6 形式 | IpAddress |
| 32文字の16進数 | FileMd5 |
| 40文字の16進数 | FileSha1 |
| 64文字の16進数 | FileSha256 |
| ドメイン名パターン | DomainName |

サンプル → [indicators_sample.csv](indicators_sample.csv)

## 使い方

```powershell
# 基本 (シークレットは対話入力)
.\Upload-MDEIndicators.ps1 -CsvPath .\indicators_sample.csv -TenantId "テナントID" -ClientId "クライアントID"

# シークレットを引数で指定
$secret = ConvertTo-SecureString "シークレット値" -AsPlainText -Force
.\Upload-MDEIndicators.ps1 -CsvPath .\indicators_sample.csv -TenantId "テナントID" -ClientId "クライアントID" -ClientSecret $secret

# 既定アクションを変更
.\Upload-MDEIndicators.ps1 -CsvPath .\indicators_sample.csv -TenantId "テナントID" -ClientId "クライアントID" -DefaultAction Alert -DefaultSeverity Medium
```

## 出力

- コンソールに各レコードの登録結果を表示 (タイプ付き: `[FileSha1]`, `[IpAddress]` 等)
- 処理完了後にサマリー (成功/失敗/スキップ) を表示
- 失敗レコードがある場合、`upload_errors_yyyyMMdd_HHmmss.csv` にエラーログを出力




---

## インジケーターの削除 (Remove-MDEIndicators.ps1)

登録済みインジケーターを CSV で一括削除します。

### 削除用 CSV フォーマット

**方法1: インジケーター ID で削除**

| 列名 | 必須 | 説明 |
|------|------|------|
| Id | ○ | インジケーターの ID (登録時に返却される数値) |

```csv
Id
12345
12346
```

**方法2: IndicatorValue で削除** (API で ID を自動検索)

| 列名 | 必須 | 説明 |
|------|------|------|
| IndicatorValue | ○ | 登録時に指定したインジケーター値 |

```csv
IndicatorValue
3395856ce81f2b7382dee72602f798b642f14140
203.0.113.50
evil-domain.example.com
```

### 使い方

```powershell
# IndicatorValue で削除
.\Remove-MDEIndicators.ps1 -CsvPath .\delete_targets.csv -TenantId "テナントID" -ClientId "クライアントID"

# -WhatIf で削除対象の確認のみ (実際には削除しない)
.\Remove-MDEIndicators.ps1 -CsvPath .\delete_targets.csv -TenantId "テナントID" -ClientId "クライアントID" -WhatIf
```



## 参考

- [POST Ti Indicator API](https://learn.microsoft.com/ja-jp/defender-endpoint/api/post-ti-indicator)
- [DELETE Indicator API](https://learn.microsoft.com/ja-jp/defender-endpoint/api/delete-ti-indicator-by-id)
