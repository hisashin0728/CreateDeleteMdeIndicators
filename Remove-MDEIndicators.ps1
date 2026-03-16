<#
.SYNOPSIS
    Microsoft Defender for Endpoint のカスタムインジケーターを一括削除するスクリプト

.DESCRIPTION
    CSV ファイルからインジケーター ID またはインジケーター値を読み取り、
    Microsoft Defender for Endpoint Delete Indicator API を使用して削除します。
    CSV に "Id" 列がある場合は直接 ID で削除します。
    "IndicatorValue" 列の場合は API で ID を検索してから削除します。
    https://learn.microsoft.com/ja-jp/defender-endpoint/api/delete-ti-indicator-by-id

.PARAMETER CsvPath
    削除するインジケーターを含む CSV ファイルのパス。
    CSV には "Id" 列 または "IndicatorValue" 列が必要です。

.PARAMETER TenantId
    Azure AD テナント ID

.PARAMETER ClientId
    アプリ登録のクライアント ID

.PARAMETER ClientSecret
    アプリ登録のクライアント シークレット (未指定時は対話的に入力)

.EXAMPLE
    .\Remove-MDEIndicators.ps1 -CsvPath .\delete_by_id.csv -TenantId "xxxx" -ClientId "yyyy"

.EXAMPLE
    .\Remove-MDEIndicators.ps1 -CsvPath .\delete_by_value.csv -TenantId "xxxx" -ClientId "yyyy"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F\-]{36}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F\-]{36}$')]
    [string]$ClientId,

    [SecureString]$ClientSecret
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$baseUrl = 'https://api.security.microsoft.com/api/indicators'

# ─────────────────────────────────────────────
# クライアントシークレットの取得
# ─────────────────────────────────────────────
if (-not $ClientSecret) {
    $ClientSecret = Read-Host -Prompt 'Client Secret を入力してください' -AsSecureString
}

$plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
)

# ─────────────────────────────────────────────
# Azure AD トークン取得
# ─────────────────────────────────────────────
function Get-AccessToken {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Secret
    )

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        client_secret = $Secret
        grant_type    = 'client_credentials'
    }

    Write-Host '[INFO] アクセストークンを取得しています...' -ForegroundColor Cyan
    $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType 'application/x-www-form-urlencoded'
    return $response.access_token
}

# ─────────────────────────────────────────────
# IndicatorValue から ID を検索
# ─────────────────────────────────────────────
function Find-IndicatorId {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$IndicatorValue
    )

    $filter = [System.Uri]::EscapeDataString("indicatorValue eq '$IndicatorValue'")
    $url = "${baseUrl}?`$filter=$filter"
    $headers = @{ Authorization = "Bearer $AccessToken" }

    $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
    if ($response.value -and $response.value.Count -gt 0) {
        return $response.value | Select-Object -ExpandProperty id
    }
    return $null
}

# ─────────────────────────────────────────────
# インジケーター削除
# ─────────────────────────────────────────────
function Remove-Indicator {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$IndicatorId
    )

    $url = "$baseUrl/$IndicatorId"
    $headers = @{ Authorization = "Bearer $AccessToken" }

    Invoke-RestMethod -Method Delete -Uri $url -Headers $headers
}

# ─────────────────────────────────────────────
# メイン処理
# ─────────────────────────────────────────────
try {
    # トークン取得
    $token = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -Secret $plainSecret

    # CSV 読み込み
    $records = Import-Csv -Path $CsvPath -Encoding UTF8
    if (-not $records) {
        Write-Error 'CSV ファイルにレコードがありません。'
        return
    }

    $columns = $records[0].PSObject.Properties.Name
    $useId    = 'Id' -in $columns
    $useValue = 'IndicatorValue' -in $columns

    if (-not $useId -and -not $useValue) {
        Write-Error "CSV に 'Id' 列 または 'IndicatorValue' 列が必要です。列: $($columns -join ', ')"
        return
    }

    if ($useId) {
        Write-Host '[INFO] Id 列を検出。インジケーター ID で直接削除します。' -ForegroundColor Cyan
    }
    else {
        Write-Host '[INFO] IndicatorValue 列を検出。値から ID を検索して削除します。' -ForegroundColor Cyan
    }

    $total   = $records.Count
    $success = 0
    $failed  = 0
    $skipped = 0
    $errors  = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "[INFO] $total 件のインジケーターを削除処理します..." -ForegroundColor Cyan

    foreach ($i in 0..($total - 1)) {
        $row = $records[$i]

        if ($useId) {
            $ids = @($row.Id.Trim())
            $displayLabel = "ID: $($ids[0])"
        }
        else {
            $value = $row.IndicatorValue.Trim()
            $displayLabel = "Value: $value"

            # IndicatorValue から ID を検索
            try {
                $foundIds = Find-IndicatorId -AccessToken $token -IndicatorValue $value
                if (-not $foundIds) {
                    Write-Warning "[$($i+1)/$total] インジケーターが見つかりません: $displayLabel"
                    $skipped++
                    continue
                }
                $ids = @($foundIds)
            }
            catch {
                $failed++
                $errMsg = $_.Exception.Message
                Write-Warning "[$($i+1)/$total] ID 検索失敗: $displayLabel - $errMsg"
                $errors.Add([PSCustomObject]@{ Target = $displayLabel; Error = $errMsg })
                continue
            }
        }

        # 削除実行 (1つの IndicatorValue に複数 ID が紐づく場合あり)
        foreach ($id in $ids) {
            if ($PSCmdlet.ShouldProcess("Indicator ID: $id", 'Delete')) {
                try {
                    Remove-Indicator -AccessToken $token -IndicatorId $id
                    $success++
                    Write-Host "[$($i+1)/$total] 削除成功: $displayLabel (ID: $id)" -ForegroundColor Green
                }
                catch {
                    $failed++
                    $errMsg = $_.Exception.Message
                    Write-Warning "[$($i+1)/$total] 削除失敗: $displayLabel (ID: $id) - $errMsg"
                    $errors.Add([PSCustomObject]@{ Target = $displayLabel; IndicatorId = $id; Error = $errMsg })
                }
            }
        }

        # API レート制限対策 (100 req/min)
        Start-Sleep -Milliseconds 700
    }

    # ─────────────────────────────────────────
    # 結果サマリー
    # ─────────────────────────────────────────
    Write-Host ''
    Write-Host '========== 削除結果 ==========' -ForegroundColor Cyan
    Write-Host "合計:     $total" -ForegroundColor White
    Write-Host "成功:     $success" -ForegroundColor Green
    Write-Host "失敗:     $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'White' })
    Write-Host "スキップ: $skipped" -ForegroundColor $(if ($skipped -gt 0) { 'Yellow' } else { 'White' })
    Write-Host '==============================' -ForegroundColor Cyan

    # エラーログ出力
    if ($errors.Count -gt 0) {
        $errorLogPath = Join-Path (Split-Path $CsvPath) "delete_errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $errors | Export-Csv -Path $errorLogPath -NoTypeInformation -Encoding UTF8
        Write-Host "[INFO] エラー詳細を出力しました: $errorLogPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "致命的エラー: $_"
    exit 1
}
finally {
    if ($plainSecret) {
        $plainSecret = $null
    }
}
