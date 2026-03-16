<#
.SYNOPSIS
    FileSha1 / FileSha256 / FileMd5 / IpAddress / DomainName / Url を
    Microsoft Defender for Endpoint のカスタムインジケーターに一括登録するスクリプト

.DESCRIPTION
    CSV ファイルからインジケーター値を読み取り、
    Microsoft Defender for Endpoint Ti Indicators API を使用してインジケーターを登録します。
    IndicatorType 列を省略した場合は値の形式から自動判定します。
    https://learn.microsoft.com/ja-jp/defender-endpoint/api/post-ti-indicator

.PARAMETER CsvPath
    登録するインジケーターを含む CSV ファイルのパス。
    CSV には最低限 "IndicatorValue" 列 (または旧形式の "Sha1" 列) が必要です。
    オプション列: IndicatorType, Title, Description, Severity, Action, ExpirationTime, RecommendedActions
    対応 IndicatorType: FileSha1, FileSha256, FileMd5, IpAddress, DomainName, Url

.PARAMETER TenantId
    Azure AD テナント ID

.PARAMETER ClientId
    アプリ登録のクライアント ID

.PARAMETER ClientSecret
    アプリ登録のクライアント シークレット (未指定時は対話的に入力)

.PARAMETER DefaultAction
    CSV に Action 列がない場合の既定アクション。
    有効値: AlertAndBlock, Alert, Allowed, Block, Audit
    既定値: AlertAndBlock

.PARAMETER DefaultSeverity
    CSV に Severity 列がない場合の既定重大度。
    有効値: Informational, Low, Medium, High
    既定値: High

.PARAMETER DefaultTitle
    CSV に Title 列がない場合の既定タイトル。

.EXAMPLE
    .\Upload-MDEIndicators.ps1 -CsvPath .\indicators.csv -TenantId "xxxx" -ClientId "yyyy"

.EXAMPLE
    .\Upload-MDEIndicators.ps1 -CsvPath .\indicators.csv -TenantId "xxxx" -ClientId "yyyy" -DefaultAction Alert -DefaultSeverity Medium
#>

[CmdletBinding()]
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

    [SecureString]$ClientSecret,

    [ValidateSet('AlertAndBlock', 'Alert', 'Allowed', 'Block', 'Audit')]
    [string]$DefaultAction = 'AlertAndBlock',

    [ValidateSet('Informational', 'Low', 'Medium', 'High')]
    [string]$DefaultSeverity = 'High',

    [string]$DefaultTitle = 'Automated Indicator Upload'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────
# インジケータータイプの自動判定
# ─────────────────────────────────────────────
function Resolve-IndicatorType {
    [CmdletBinding()]
    param([string]$Value)

    switch -Regex ($Value) {
        # URL (スキーム付き)
        '^https?://'                        { return 'Url' }
        # IPv4
        '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' { return 'IpAddress' }
        # IPv6 (簡易判定)
        '^[0-9a-fA-F:]{2,39}$'             { if ($Value -match ':') { return 'IpAddress' } }
        # MD5 (32 hex)
        '^[0-9a-fA-F]{32}$'                { return 'FileMd5' }
        # SHA1 (40 hex)
        '^[0-9a-fA-F]{40}$'                { return 'FileSha1' }
        # SHA256 (64 hex)
        '^[0-9a-fA-F]{64}$'                { return 'FileSha256' }
        # ドメイン名 (基本パターン)
        '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' { return 'DomainName' }
    }
    return $null
}

# ─────────────────────────────────────────────
# インジケーター値のバリデーション
# ─────────────────────────────────────────────
function Test-IndicatorValue {
    [CmdletBinding()]
    param(
        [string]$Value,
        [string]$Type
    )

    switch ($Type) {
        'FileSha1'   { return $Value -match '^[0-9a-fA-F]{40}$' }
        'FileSha256' { return $Value -match '^[0-9a-fA-F]{64}$' }
        'FileMd5'    { return $Value -match '^[0-9a-fA-F]{32}$' }
        'IpAddress'  {
            # IPv4
            if ($Value -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $octets = $Value -split '\.' | ForEach-Object { [int]$_ }
                return ($octets | Where-Object { $_ -ge 0 -and $_ -le 255 }).Count -eq 4
            }
            # IPv6 (簡易)
            return $Value -match '^[0-9a-fA-F:]{2,39}$' -and $Value -match ':'
        }
        'DomainName' { return $Value -match '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' }
        'Url'        { return $Value -match '^https?://.+' }
        default      { return $false }
    }
}

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
# インジケーター登録
# ─────────────────────────────────────────────
function Submit-Indicator {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [hashtable]$IndicatorBody
    )

    $apiUrl = 'https://api.security.microsoft.com/api/indicators'
    $headers = @{
        Authorization  = "Bearer $AccessToken"
        'Content-Type' = 'application/json'
    }

    $jsonBody = $IndicatorBody | ConvertTo-Json -Depth 5
    $response = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $jsonBody
    return $response
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

    # 列の存在確認 (IndicatorValue または旧形式の Sha1)
    $columns = $records[0].PSObject.Properties.Name
    $useLegacySha1 = $false
    if ('IndicatorValue' -notin $columns) {
        if ('Sha1' -in $columns) {
            $useLegacySha1 = $true
            Write-Host '[INFO] 旧形式 (Sha1 列) を検出。IndicatorValue として処理します。' -ForegroundColor Yellow
        }
        else {
            Write-Error "CSV に 'IndicatorValue' 列 (または 'Sha1' 列) が見つかりません。列: $($columns -join ', ')"
            return
        }
    }

    $hasTypeColumn = 'IndicatorType' -in $columns

    $total   = $records.Count
    $success = 0
    $failed  = 0
    $skipped = 0
    $errors  = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "[INFO] $total 件のインジケーターを処理します..." -ForegroundColor Cyan

    foreach ($i in 0..($total - 1)) {
        $row = $records[$i]

        # インジケーター値の取得
        $indicatorValue = if ($useLegacySha1) { $row.Sha1.Trim() } else { $row.IndicatorValue.Trim() }

        # インジケータータイプの決定
        if ($useLegacySha1) {
            $indicatorType = 'FileSha1'
        }
        elseif ($hasTypeColumn -and $row.IndicatorType) {
            $indicatorType = $row.IndicatorType.Trim()
        }
        else {
            $indicatorType = Resolve-IndicatorType -Value $indicatorValue
            if (-not $indicatorType) {
                Write-Warning "[$($i+1)/$total] タイプ判定不能のためスキップ: $indicatorValue"
                $skipped++
                continue
            }
        }

        # バリデーション
        if (-not (Test-IndicatorValue -Value $indicatorValue -Type $indicatorType)) {
            Write-Warning "[$($i+1)/$total] 無効な $indicatorType をスキップ: $indicatorValue"
            $skipped++
            continue
        }

        # 行ごとのオーバーライドを取得 (CSV 列があればその値を使用)
        $action      = if ($columns -contains 'Action'      -and $row.Action)             { $row.Action }             else { $DefaultAction }
        $severity    = if ($columns -contains 'Severity'    -and $row.Severity)            { $row.Severity }           else { $DefaultSeverity }
        $title       = if ($columns -contains 'Title'       -and $row.Title)               { $row.Title }              else { $DefaultTitle }
        $description = if ($columns -contains 'Description' -and $row.Description)         { $row.Description }        else { "Indicator uploaded on $(Get-Date -Format 'yyyy-MM-dd HH:mm')" }
        $recActions  = if ($columns -contains 'RecommendedActions' -and $row.RecommendedActions) { $row.RecommendedActions } else { '' }

        $body = @{
            indicatorValue     = $indicatorValue
            indicatorType      = $indicatorType
            action             = $action
            title              = $title
            description        = $description
            severity           = $severity
            generateAlert      = $true
        }

        if ($recActions) {
            $body['recommendedActions'] = $recActions
        }

        # ExpirationTime (ISO 8601)
        if ($columns -contains 'ExpirationTime' -and $row.ExpirationTime) {
            $body['expirationTime'] = $row.ExpirationTime
        }

        try {
            $result = Submit-Indicator -AccessToken $token -IndicatorBody $body
            $success++
            Write-Host "[$($i+1)/$total] 登録成功: [$indicatorType] $indicatorValue (ID: $($result.id))" -ForegroundColor Green
        }
        catch {
            $failed++
            $errMsg = $_.Exception.Message
            Write-Warning "[$($i+1)/$total] 登録失敗: [$indicatorType] $indicatorValue - $errMsg"
            $errors.Add([PSCustomObject]@{
                IndicatorValue = $indicatorValue
                IndicatorType  = $indicatorType
                Error          = $errMsg
            })
        }

        # API レート制限対策 (100 req/min)
        Start-Sleep -Milliseconds 700
    }

    # ─────────────────────────────────────────
    # 結果サマリー
    # ─────────────────────────────────────────
    Write-Host ''
    Write-Host '========== 処理結果 ==========' -ForegroundColor Cyan
    Write-Host "合計:     $total" -ForegroundColor White
    Write-Host "成功:     $success" -ForegroundColor Green
    Write-Host "失敗:     $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'White' })
    Write-Host "スキップ: $skipped" -ForegroundColor $(if ($skipped -gt 0) { 'Yellow' } else { 'White' })
    Write-Host '==============================' -ForegroundColor Cyan

    # エラーログ出力
    if ($errors.Count -gt 0) {
        $errorLogPath = Join-Path (Split-Path $CsvPath) "upload_errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $errors | Export-Csv -Path $errorLogPath -NoTypeInformation -Encoding UTF8
        Write-Host "[INFO] エラー詳細を出力しました: $errorLogPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "致命的エラー: $_"
    exit 1
}
finally {
    # シークレットをメモリからクリア
    if ($plainSecret) {
        $plainSecret = $null
    }
}
