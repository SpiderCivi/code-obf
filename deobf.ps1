# =============================================================
# CODE-OBF deobfuscator standalone (PowerShell)
# =============================================================
# Uso:
#   .\deobf.ps1 -FilePath <file_o_cartella> -KeyFile <keyfile> [-Password <pwd>]
#   .\deobf.ps1 -FilePath <cartella>        (deofusca tutti + verifica)
#   .\deobf.ps1                              (interattivo)
# =============================================================

param(
    [string]$FilePath   = "",
    [string]$KeyFile    = "",
    [string]$Password   = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$ITER = 200000
$META_PATTERN = "\[CODE-OBF-META\]\s+mode=([KPB])\s+salt=([0-9a-f]+)\s+iv=([0-9a-f]+)\s+tag=([0-9a-f]+)\s+ct=([0-9a-f]+)"
$SUPPORTED_EXT = @(".py",".js",".mjs",".ts",".ps1",".sh")

function From-Hex([string]$h) {
    $o = New-Object byte[] ($h.Length / 2)
    for ($i = 0; $i -lt $o.Length; $i++) {
        $o[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16)
    }
    , $o
}

function Sha256([byte[]]$data) {
    $s = [System.Security.Cryptography.SHA256]::Create()
    try { $s.ComputeHash($data) } finally { $s.Dispose() }
}

function Hmac256([byte[]]$key, [byte[]]$data) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, $key)
    try { $h.ComputeHash($data) } finally { $h.Dispose() }
}

function Pbkdf2([string]$pwd, [byte[]]$salt, [int]$it, [int]$len) {
    $k = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pwd, $salt, $it, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $k.GetBytes($len) } finally { $k.Dispose() }
}

function Keystream([byte[]]$mk, [byte[]]$iv, [int]$len) {
    $blocks = [math]::Ceiling($len / 32.0)
    $ks = New-Object byte[] ($blocks * 32)
    for ($i = 0; $i -lt $blocks; $i++) {
        $ctr = [byte[]]@(
            [byte](($i -shr 24) -band 0xFF),
            [byte](($i -shr 16) -band 0xFF),
            [byte](($i -shr  8) -band 0xFF),
            [byte]( $i          -band 0xFF)
        )
        $buf = New-Object byte[] ($mk.Length + $iv.Length + 4)
        [Array]::Copy($mk,  0, $buf, 0,                             $mk.Length)
        [Array]::Copy($iv,  0, $buf, $mk.Length,                    $iv.Length)
        [Array]::Copy($ctr, 0, $buf, $mk.Length + $iv.Length,      4)
        $hash = Sha256 $buf
        [Array]::Copy($hash, 0, $ks, $i * 32, 32)
    }
    $out = New-Object byte[] $len
    [Array]::Copy($ks, 0, $out, 0, $len)
    , $out
}

function Is-Hex64([string]$s) {
    return ($s.Length -eq 64) -and ($s -match "^[0-9a-fA-F]{64}$")
}

function Derive-Key([string]$mode, [byte[]]$salt, [string]$kfContent, [string]$pass) {
    if ($mode -eq "K") {
        if (Is-Hex64 $kfContent) { return (From-Hex $kfContent) }
        return (Pbkdf2 $kfContent $salt $ITER 32)
    }
    if ($mode -eq "P") {
        return (Pbkdf2 $pass $salt $ITER 32)
    }
    if ($mode -eq "B") {
        $combined = $pass + "|" + $kfContent
        return (Pbkdf2 $combined $salt $ITER 32)
    }
    throw "Mode sconosciuto: $mode"
}

function Read-SecurePass([string]$prompt) {
    $ss = Read-Host $prompt -AsSecureString
    $bs = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bs) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bs) }
}

function Parse-Meta([string]$filePath) {
    try {
        $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
    } catch {
        return $null
    }
    if ($content -match $META_PATTERN) {
        return @{
            mode = $Matches[1]
            salt = (From-Hex $Matches[2])
            iv   = (From-Hex $Matches[3])
            tag  = (From-Hex $Matches[4])
            ct   = (From-Hex $Matches[5])
        }
    }
    return $null
}

function Deobf-File([string]$filePath, [string]$outPath, [string]$kfContent, [string]$pass) {
    $meta = Parse-Meta $filePath
    if (-not $meta) {
        Write-Host "  [skip] header non trovato: $filePath" -ForegroundColor DarkGray
        return $false
    }
    $mk = Derive-Key $meta.mode $meta.salt $kfContent $pass

    $authBuf = New-Object byte[] ($meta.iv.Length + $meta.ct.Length)
    [Array]::Copy($meta.iv, 0, $authBuf, 0,                $meta.iv.Length)
    [Array]::Copy($meta.ct, 0, $authBuf, $meta.iv.Length,  $meta.ct.Length)
    $fullTag = Hmac256 $mk $authBuf
    for ($i = 0; $i -lt 16; $i++) {
        if ($fullTag[$i] -ne $meta.tag[$i]) {
            Write-Host "  [FAIL] HMAC invalido: $filePath" -ForegroundColor Red
            return $false
        }
    }

    $ks = Keystream $mk $meta.iv $meta.ct.Length
    $pt = New-Object byte[] $meta.ct.Length
    for ($i = 0; $i -lt $meta.ct.Length; $i++) {
        $pt[$i] = [byte]($meta.ct[$i] -bxor $ks[$i])
    }

    $outDir = Split-Path $outPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllBytes($outPath, $pt)
    Write-Host "  [OK]   $(Split-Path $filePath -Leaf) -> $outPath  ($($pt.Length) bytes)" -ForegroundColor Green
    return $true
}

# ============ MAIN ============

Write-Host ""
Write-Host "=== CODE-OBF deobfuscator (standalone) ===" -ForegroundColor Cyan
Write-Host ""

if (-not $FilePath) {
    $FilePath = (Read-Host "File o cartella da deofuscare").Trim('"').Trim("'")
}
if (-not (Test-Path $FilePath)) {
    Write-Host "Path non trovato: $FilePath" -ForegroundColor Red
    exit 1
}

$isDir = (Get-Item $FilePath).PSIsContainer

# $baseDir = root per calcolare i path relativi (cartella input o parent del file)
# $outRoot = dove scrivere i file deofuscati (sottocartella 'deobf' di default)
if ($isDir) {
    $baseDir = (Resolve-Path $FilePath).Path
    if (-not $OutputPath) { $OutputPath = Join-Path $baseDir "deobf" }
} else {
    $baseDir = [System.IO.Path]::GetDirectoryName((Resolve-Path $FilePath).Path)
    if (-not $OutputPath) { $OutputPath = Join-Path $baseDir "deobf" }
}
$outRoot = $OutputPath

$targets = @()
if ($isDir) {
    Write-Host "Scansione cartella: $FilePath" -ForegroundColor Cyan
    $all = Get-ChildItem -Path $FilePath -File -Recurse | Where-Object {
        ($SUPPORTED_EXT -contains $_.Extension.ToLower())
    }
    foreach ($f in $all) {
        if (Parse-Meta $f.FullName) { $targets += $f.FullName }
    }
    Write-Host "  Trovati $($targets.Count) file obfuscati (su $($all.Count) compatibili)" -ForegroundColor Cyan
    if ($targets.Count -eq 0) { Write-Host "Nessun file da deofuscare." -ForegroundColor Yellow; exit 0 }
} else {
    $targets = @((Resolve-Path $FilePath).Path)
}
Write-Host "Output: $outRoot" -ForegroundColor Cyan

$modes = @{}
foreach ($t in $targets) {
    $m = Parse-Meta $t
    if ($m) { $modes[$m.mode] = $true }
}

$needsKey  = $modes.ContainsKey("K") -or $modes.ContainsKey("B")
$needsPass = $modes.ContainsKey("P") -or $modes.ContainsKey("B")

Write-Host "Auth mode rilevati nei file: $($modes.Keys -join ', ')" -ForegroundColor Cyan

$kfContent = ""
if ($needsKey) {
    if (-not $KeyFile) {
        if ($env:CODE_OBF_KEY) { $KeyFile = $env:CODE_OBF_KEY }
        else { $KeyFile = (Read-Host "Path keyfile").Trim('"').Trim("'") }
    }
    if (-not (Test-Path $KeyFile)) {
        Write-Host "Keyfile non trovato: $KeyFile" -ForegroundColor Red
        exit 1
    }
    $kfContent = (Get-Content $KeyFile -Raw).Trim()
}

if ($needsPass) {
    if (-not $Password) {
        if ($env:CODE_OBF_PASS) { $Password = $env:CODE_OBF_PASS }
        else { $Password = Read-SecurePass "Password" }
    }
}

Write-Host ""
Write-Host "Deofuscazione in corso..." -ForegroundColor Yellow
$okCount   = 0
$failCount = 0
$failList  = @()
foreach ($t in $targets) {
    # Calcola output path mantenendo il nome originale + struttura sottocartelle
    $rel = $t.Substring($baseDir.Length).TrimStart('\','/')
    if (-not $rel) { $rel = Split-Path $t -Leaf }
    $outPath = Join-Path $outRoot $rel
    if (Deobf-File $t $outPath $kfContent $Password) {
        $okCount++
    } else {
        $failCount++
        $failList += $t
    }
}

# Verifica finale: controlla che ogni target abbia il suo .deobf.ext non vuoto
Write-Host ""
Write-Host "Verifica integrita output..." -ForegroundColor Yellow
$missing = @()
foreach ($t in $targets) {
    $rel = $t.Substring($baseDir.Length).TrimStart('\','/')
    if (-not $rel) { $rel = Split-Path $t -Leaf }
    $out = Join-Path $outRoot $rel
    if (-not (Test-Path $out)) {
        $missing += $t
    } elseif ((Get-Item $out).Length -eq 0) {
        $missing += "$t (output vuoto)"
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  RISULTATO DEOFUSCAZIONE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  File totali:      $($targets.Count)"
Write-Host "  Deofuscati OK:    $okCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "  Falliti:          $failCount" -ForegroundColor Red
    foreach ($f in $failList) { Write-Host "     - $f" -ForegroundColor Red }
}
if ($missing.Count -gt 0) {
    Write-Host "  Output mancanti:  $($missing.Count)" -ForegroundColor Red
    foreach ($m in $missing) { Write-Host "     - $m" -ForegroundColor Red }
}
Write-Host "============================================================" -ForegroundColor Cyan

if ($okCount -eq $targets.Count -and $missing.Count -eq 0) {
    Write-Host "TUTTI I FILE DEOFUSCATI CORRETTAMENTE." -ForegroundColor Green
    exit 0
} else {
    Write-Host "DEOFUSCAZIONE INCOMPLETA: alcuni file non recuperati." -ForegroundColor Red
    exit 1
}
