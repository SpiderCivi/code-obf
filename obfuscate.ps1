# ============================================================================
# CODE-OBF v3 ??" Obfuscatore con Keyfile, Password, o Entrambi (2FA)
# ============================================================================
#
# CRYPTO: SHA256-CTR stream cipher + HMAC-SHA256 auth tag + PBKDF2 (200k iter)
#
# MODALIT?? AUTENTICAZIONE (-Auth):
#   keyfile   ??' serve il file .key (default, comportamento storico)
#   password  ??' serve la password (digitata o via env CODE_OBF_PASS)
#   both      ??' servono ENTRAMBI (2 fattori)
#
# PARAMETRI:
#   -Mode <obfuscate|deobfuscate>
#   -Auth <keyfile|password|both>
#   -ProjectPath <path>  -OutputPath <path>  -FilePath <path>
#   -KeyFile <path>      -Password <string>  (se omesso, chiede)
#
# LINGUAGGI: .py .js .mjs .ts .ps1 .sh
# Note: wrapper JS/TS per Auth=password|both richiedono CODE_OBF_PASS
#       (Node non supporta prompt password sincrono senza librerie esterne).
# ============================================================================

param(
    [ValidateSet("obfuscate","deobfuscate")]
    [string]$Mode = "obfuscate",

    [ValidateSet("keyfile","password","both")]
    [string]$Auth = "keyfile",

    [string]$ProjectPath = "",
    [string]$OutputPath  = "",
    [string]$FilePath    = "",
    [string]$KeyFile     = "",
    [string]$Password    = ""
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "??"????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????-" -ForegroundColor Cyan
Write-Host "??'  CODE-OBF v3  ??"  Keyfile / Password / 2FA           ??'" -ForegroundColor Cyan
Write-Host "??'  SHA256-CTR + HMAC-SHA256 + PBKDF2-200k             ??'" -ForegroundColor Cyan
Write-Host "????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????" -ForegroundColor Cyan
Write-Host ""

# PBKDF2 iteration count (balance sicurezza / UX)
$PBKDF2_ITER = 200000

# ============================================================================
# CRYPTO CORE
# ============================================================================

function ConvertTo-HexString([byte[]]$bytes) {
    $sb = New-Object System.Text.StringBuilder ($bytes.Length * 2)
    foreach ($b in $bytes) { [void]$sb.AppendFormat("{0:x2}", $b) }
    return $sb.ToString()
}

function ConvertFrom-HexString([string]$hex) {
    $hex = $hex.Trim()
    $out = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) {
        $out[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $out
}

function Test-IsHex64([string]$s) {
    return ($s.Length -eq 64) -and ($s -match '^[0-9a-fA-F]{64}$')
}

function Get-RandomBytes([int]$n) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return $b
}

function Get-Sha256([byte[]]$data) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($data) } finally { $sha.Dispose() }
}

function Get-HmacSha256([byte[]]$key, [byte[]]$data) {
    $h = New-Object System.Security.Cryptography.HMACSHA256 (,$key)
    try { return $h.ComputeHash($data) } finally { $h.Dispose() }
}

function Get-Pbkdf2([string]$password, [byte[]]$salt, [int]$iter, [int]$len) {
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return $kdf.GetBytes($len) } finally { $kdf.Dispose() }
}

function Get-Keystream([byte[]]$masterKey, [byte[]]$iv, [int]$len) {
    $blocks = [math]::Ceiling($len / 32.0)
    $ks = New-Object byte[] ($blocks * 32)
    for ($i = 0; $i -lt $blocks; $i++) {
        $ctr = [byte[]]@(
            [byte](($i -shr 24) -band 0xFF),
            [byte](($i -shr 16) -band 0xFF),
            [byte](($i -shr  8) -band 0xFF),
            [byte]( $i         -band 0xFF)
        )
        $buf = New-Object byte[] ($masterKey.Length + $iv.Length + 4)
        [Array]::Copy($masterKey, 0, $buf, 0, $masterKey.Length)
        [Array]::Copy($iv, 0, $buf, $masterKey.Length, $iv.Length)
        [Array]::Copy($ctr, 0, $buf, $masterKey.Length + $iv.Length, 4)
        $hash = Get-Sha256 $buf
        [Array]::Copy($hash, 0, $ks, $i * 32, 32)
    }
    $out = New-Object byte[] $len
    [Array]::Copy($ks, 0, $out, 0, $len)
    return $out
}

function Invoke-StreamXor([byte[]]$data, [byte[]]$keystream) {
    $out = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {
        $out[$i] = [byte]($data[$i] -bxor $keystream[$i])
    }
    return $out
}

# ============================================================================
# MASTER KEY DERIVATION (scelta mode)
# ============================================================================

function Get-MasterKey([string]$authMode, [string]$keyFilePath, [string]$pass, [byte[]]$salt) {
    # Ritorna 32 bytes di chiave master a seconda dell'Auth mode.
    switch ($authMode) {
        "keyfile" {
            if (-not (Test-Path $keyFilePath)) {
                throw "Keyfile non trovato: $keyFilePath"
            }
            $content = (Get-Content $keyFilePath -Raw).Trim()
            if (Test-IsHex64 $content) {
                return (ConvertFrom-HexString $content)
            } else {
                return (Get-Pbkdf2 $content $salt $PBKDF2_ITER 32)
            }
        }
        "password" {
            if ([string]::IsNullOrEmpty($pass)) { throw "Password mancante." }
            return (Get-Pbkdf2 $pass $salt $PBKDF2_ITER 32)
        }
        "both" {
            if (-not (Test-Path $keyFilePath)) { throw "Keyfile non trovato: $keyFilePath" }
            if ([string]::IsNullOrEmpty($pass))  { throw "Password mancante." }
            $content = (Get-Content $keyFilePath -Raw).Trim()
            $combined = $pass + '|' + $content
            return (Get-Pbkdf2 $combined $salt $PBKDF2_ITER 32)
        }
    }
}

# ============================================================================
# KEYFILE MANAGEMENT
# ============================================================================

function Get-OrCreateKeyFile([string]$keyFilePath, [bool]$randomHex) {
    # Se randomHex e' vero e il file non esiste, ne genera uno con 64 hex random.
    # Se randomHex e' falso, richiede che il file esista (caso password-file).
    if (Test-Path $keyFilePath) {
        Write-Host "  Keyfile esistente: $keyFilePath" -ForegroundColor DarkGray
        return
    }
    if (-not $randomHex) {
        throw "Keyfile non trovato: $keyFilePath. Crealo prima (inserisci la tua password dentro)."
    }
    $mk  = Get-RandomBytes 32
    $hex = ConvertTo-HexString $mk
    $dir = Split-Path $keyFilePath -Parent
    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $keyFilePath -Value $hex -NoNewline -Encoding ASCII
    Write-Host "  Nuovo keyfile generato a $keyFilePath" -ForegroundColor Yellow
    Write-Host "  CUSTODISCI QUESTO FILE" -ForegroundColor Red
}

function Read-SecurePassword([string]$prompt) {
    $ss = Read-Host $prompt -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ============================================================================
# WRAPPER GENERATORS (self-decoder, per ogni linguaggio)
# ============================================================================

function New-PythonWrapper([string]$mode, [string]$saltHex, [string]$ivHex, [string]$tagHex, [string]$ctHex, [string]$srcName, [int]$iter) {
    return @"
# [CODE-OBF v3] $srcName | auth=$mode | SHA256-CTR + HMAC + PBKDF2
# [CODE-OBF-META] mode=$mode salt=$saltHex iv=$ivHex tag=$tagHex ct=$ctHex
import os,sys,hmac,hashlib,struct
try:
    import getpass as _gp
except Exception:
    _gp=None
_MODE='$mode'
_ITER=$iter
_salt=bytes.fromhex('$saltHex');_iv=bytes.fromhex('$ivHex');_ct=bytes.fromhex('$ctHex');_tag=bytes.fromhex('$tagHex')
def _read_key():
    kp=os.environ.get('CODE_OBF_KEY') or 'code-obf.key'
    try: return open(kp).read().strip()
    except Exception as e: sys.exit('[CODE-OBF] keyfile non trovato (%s): %s' % (kp, e))
def _read_pass():
    p=os.environ.get('CODE_OBF_PASS')
    if p: return p
    if _gp is None: sys.exit('[CODE-OBF] password richiesta: imposta CODE_OBF_PASS')
    try: return _gp.getpass('[CODE-OBF] password: ')
    except Exception: sys.exit('[CODE-OBF] password richiesta')
def _derive():
    if _MODE=='K':
        c=_read_key()
        if len(c)==64 and all(x in '0123456789abcdefABCDEF' for x in c):
            return bytes.fromhex(c)
        return hashlib.pbkdf2_hmac('sha256',c.encode('utf-8'),_salt,_ITER,32)
    if _MODE=='P':
        return hashlib.pbkdf2_hmac('sha256',_read_pass().encode('utf-8'),_salt,_ITER,32)
    if _MODE=='B':
        c=_read_key();p=_read_pass()
        return hashlib.pbkdf2_hmac('sha256',(p+'|'+c).encode('utf-8'),_salt,_ITER,32)
    sys.exit('[CODE-OBF] mode sconosciuto: '+_MODE)
_mk=_derive()
if not hmac.compare_digest(hmac.new(_mk,_iv+_ct,hashlib.sha256).digest()[:16],_tag):
    sys.exit('[CODE-OBF] HMAC invalido: credenziali sbagliate o file manomesso')
_n=(len(_ct)+31)//32
_ks=b''.join(hashlib.sha256(_mk+_iv+struct.pack('>I',_i)).digest() for _i in range(_n))[:len(_ct)]
exec(compile(bytes(a^b for a,b in zip(_ct,_ks)),'<$srcName>','exec'))
"@
}

function New-JsWrapper([string]$mode, [string]$saltHex, [string]$ivHex, [string]$tagHex, [string]$ctHex, [string]$srcName, [int]$iter) {
    return @"
// [CODE-OBF v3] $srcName | auth=$mode | SHA256-CTR + HMAC + PBKDF2
// [CODE-OBF-META] mode=$mode salt=$saltHex iv=$ivHex tag=$tagHex ct=$ctHex
(()=>{const c=require('crypto'),f=require('fs');
const MODE='$mode',ITER=$iter;
const salt=Buffer.from('$saltHex','hex'),iv=Buffer.from('$ivHex','hex'),ct=Buffer.from('$ctHex','hex'),tag=Buffer.from('$tagHex','hex');
function rk(){const kp=process.env.CODE_OBF_KEY||'code-obf.key';try{return f.readFileSync(kp,'utf8').trim()}catch(e){console.error('[CODE-OBF] keyfile non trovato: '+kp);process.exit(1)}}
function rp(){const p=process.env.CODE_OBF_PASS;if(!p){console.error('[CODE-OBF] password richiesta: imposta CODE_OBF_PASS');process.exit(1)}return p}
function derive(){
  if(MODE==='K'){const s=rk();if(/^[0-9a-fA-F]{64}$/.test(s))return Buffer.from(s,'hex');return c.pbkdf2Sync(s,salt,ITER,32,'sha256')}
  if(MODE==='P')return c.pbkdf2Sync(rp(),salt,ITER,32,'sha256');
  if(MODE==='B'){const s=rk(),p=rp();return c.pbkdf2Sync(p+'|'+s,salt,ITER,32,'sha256')}
  console.error('[CODE-OBF] mode sconosciuto: '+MODE);process.exit(1)
}
const mk=derive();
const hm=c.createHmac('sha256',mk).update(Buffer.concat([iv,ct])).digest().slice(0,16);
if(!c.timingSafeEqual(hm,tag)){console.error('[CODE-OBF] HMAC invalido: credenziali sbagliate o file manomesso');process.exit(1)}
const n=Math.ceil(ct.length/32),parts=[];
for(let i=0;i<n;i++){const b=Buffer.alloc(4);b.writeUInt32BE(i);parts.push(c.createHash('sha256').update(Buffer.concat([mk,iv,b])).digest())}
const ks=Buffer.concat(parts).slice(0,ct.length),pt=Buffer.alloc(ct.length);
for(let i=0;i<ct.length;i++)pt[i]=ct[i]^ks[i];
(0,eval)(pt.toString('utf8'));})();
"@
}

function New-TypeScriptWrapper([string]$mode, [string]$saltHex, [string]$ivHex, [string]$tagHex, [string]$ctHex, [string]$srcName, [int]$iter) {
    return @"
// [CODE-OBF v3] $srcName | auth=$mode | SHA256-CTR + HMAC + PBKDF2
// [CODE-OBF-META] mode=$mode salt=$saltHex iv=$ivHex tag=$tagHex ct=$ctHex
(()=>{const c=require('crypto'),f=require('fs');
const MODE:string='$mode',ITER:number=$iter;
const salt=Buffer.from('$saltHex','hex'),iv=Buffer.from('$ivHex','hex'),ct=Buffer.from('$ctHex','hex'),tag=Buffer.from('$tagHex','hex');
function rk():string{const kp=process.env.CODE_OBF_KEY||'code-obf.key';try{return f.readFileSync(kp,'utf8').trim()}catch(e){console.error('[CODE-OBF] keyfile non trovato: '+kp);process.exit(1);throw e}}
function rp():string{const p=process.env.CODE_OBF_PASS;if(!p){console.error('[CODE-OBF] password richiesta: imposta CODE_OBF_PASS');process.exit(1);throw new Error()}return p}
function derive():Buffer{
  if(MODE==='K'){const s=rk();if(/^[0-9a-fA-F]{64}$/.test(s))return Buffer.from(s,'hex');return c.pbkdf2Sync(s,salt,ITER,32,'sha256')}
  if(MODE==='P')return c.pbkdf2Sync(rp(),salt,ITER,32,'sha256');
  if(MODE==='B'){const s=rk(),p=rp();return c.pbkdf2Sync(p+'|'+s,salt,ITER,32,'sha256')}
  console.error('[CODE-OBF] mode sconosciuto');process.exit(1);throw new Error()
}
const mk=derive();
const hm=c.createHmac('sha256',mk).update(Buffer.concat([iv,ct])).digest().slice(0,16);
if(!c.timingSafeEqual(hm,tag)){console.error('[CODE-OBF] HMAC invalido');process.exit(1)}
const n=Math.ceil(ct.length/32),parts:Buffer[]=[];
for(let i=0;i<n;i++){const b=Buffer.alloc(4);b.writeUInt32BE(i);parts.push(c.createHash('sha256').update(Buffer.concat([mk,iv,b])).digest())}
const ks=Buffer.concat(parts).slice(0,ct.length),pt=Buffer.alloc(ct.length);
for(let i=0;i<ct.length;i++)pt[i]=ct[i]^ks[i];
new Function(pt.toString('utf8'))();})();
"@
}

function New-PowerShellWrapper([string]$mode, [string]$saltHex, [string]$ivHex, [string]$tagHex, [string]$ctHex, [string]$srcName, [int]$iter) {
    return @"
# [CODE-OBF v3] $srcName | auth=$mode | SHA256-CTR + HMAC + PBKDF2
# [CODE-OBF-META] mode=$mode salt=$saltHex iv=$ivHex tag=$tagHex ct=$ctHex
`$_MODE='$mode';`$_ITER=$iter
function _h2b([string]`$h){`$o=New-Object byte[] (`$h.Length/2);for(`$i=0;`$i -lt `$o.Length;`$i++){`$o[`$i]=[Convert]::ToByte(`$h.Substring(`$i*2,2),16)};,`$o}
`$_salt=_h2b '$saltHex';`$_iv=_h2b '$ivHex';`$_ct=_h2b '$ctHex';`$_tag=_h2b '$tagHex'
function _rk{`$kp=if(`$env:CODE_OBF_KEY){`$env:CODE_OBF_KEY}else{'code-obf.key'};if(-not(Test-Path `$kp)){Write-Error "[CODE-OBF] keyfile non trovato: `$kp";exit 1};(Get-Content `$kp -Raw).Trim()}
function _rp{if(`$env:CODE_OBF_PASS){return `$env:CODE_OBF_PASS};`$ss=Read-Host "[CODE-OBF] password" -AsSecureString;`$bs=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$ss);try{[System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$bs)}finally{[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$bs)}}
function _pbk([string]`$s,[byte[]]`$salt,[int]`$it){`$k=New-Object System.Security.Cryptography.Rfc2898DeriveBytes(`$s,`$salt,`$it,[System.Security.Cryptography.HashAlgorithmName]::SHA256);try{`$k.GetBytes(32)}finally{`$k.Dispose()}}
function _derive{
  if(`$_MODE -eq 'K'){`$c=_rk;if(`$c.Length -eq 64 -and `$c -match '^[0-9a-fA-F]{64}`$'){return _h2b `$c};return _pbk `$c `$_salt `$_ITER}
  if(`$_MODE -eq 'P'){return _pbk (_rp) `$_salt `$_ITER}
  if(`$_MODE -eq 'B'){`$c=_rk;`$p=_rp;return _pbk "`$p|`$c" `$_salt `$_ITER}
  Write-Error "[CODE-OBF] mode sconosciuto";exit 1
}
`$_mk=_derive
`$_auth=New-Object byte[] (`$_iv.Length+`$_ct.Length);[Array]::Copy(`$_iv,0,`$_auth,0,`$_iv.Length);[Array]::Copy(`$_ct,0,`$_auth,`$_iv.Length,`$_ct.Length)
`$_h=New-Object System.Security.Cryptography.HMACSHA256(,`$_mk);`$_hm=`$_h.ComputeHash(`$_auth);`$_h.Dispose()
`$_ok=`$true;for(`$i=0;`$i -lt 16;`$i++){if(`$_hm[`$i] -ne `$_tag[`$i]){`$_ok=`$false;break}}
if(-not `$_ok){Write-Error "[CODE-OBF] HMAC invalido";exit 1}
`$_n=[math]::Ceiling(`$_ct.Length/32.0);`$_ks=New-Object byte[] (`$_n*32)
`$_sha=[System.Security.Cryptography.SHA256]::Create()
for(`$i=0;`$i -lt `$_n;`$i++){
  `$_c=[byte[]]@([byte]((`$i -shr 24) -band 0xFF),[byte]((`$i -shr 16) -band 0xFF),[byte]((`$i -shr 8) -band 0xFF),[byte](`$i -band 0xFF))
  `$_b=New-Object byte[] (`$_mk.Length+`$_iv.Length+4);[Array]::Copy(`$_mk,0,`$_b,0,`$_mk.Length);[Array]::Copy(`$_iv,0,`$_b,`$_mk.Length,`$_iv.Length);[Array]::Copy(`$_c,0,`$_b,`$_mk.Length+`$_iv.Length,4)
  `$_hh=`$_sha.ComputeHash(`$_b);[Array]::Copy(`$_hh,0,`$_ks,`$i*32,32)
}
`$_sha.Dispose()
`$_pt=New-Object byte[] `$_ct.Length
for(`$i=0;`$i -lt `$_ct.Length;`$i++){`$_pt[`$i]=[byte](`$_ct[`$i] -bxor `$_ks[`$i])}
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString(`$_pt))
"@
}

function New-ShellWrapper([string]$mode, [string]$saltHex, [string]$ivHex, [string]$tagHex, [string]$ctHex, [string]$srcName, [int]$iter) {
    # Bash wrapper usa python3 come fallback per PBKDF2 (stdlib, cross-platform).
    return @"
#!/bin/bash
# [CODE-OBF v3] $srcName | auth=$mode | SHA256-CTR + HMAC + PBKDF2 (richiede python3 + openssl + xxd)
# [CODE-OBF-META] mode=$mode salt=$saltHex iv=$ivHex tag=$tagHex ct=$ctHex
set -e
MODE='$mode'; ITER=$iter
salt='$saltHex'; iv='$ivHex'; ct='$ctHex'; tag='$tagHex'
read_key(){ local kp="`${CODE_OBF_KEY:-code-obf.key}"; [ -f "`$kp" ] || { echo "[CODE-OBF] keyfile non trovato: `$kp" >&2; exit 1; }; tr -d '[:space:]' < "`$kp"; }
read_pass(){ if [ -n "`$CODE_OBF_PASS" ]; then printf '%s' "`$CODE_OBF_PASS"; else read -r -s -p "[CODE-OBF] password: " p; echo >&2; printf '%s' "`$p"; fi; }
pbkdf2(){ python3 -c "import hashlib,sys; sys.stdout.buffer.write(hashlib.pbkdf2_hmac('sha256',sys.argv[1].encode(),bytes.fromhex(sys.argv[2]),int(sys.argv[3]),32))" "`$1" "`$salt" "`$ITER" | xxd -p -c999; }
derive(){
  case "`$MODE" in
    K) c=`$(read_key); if [[ "`$c" =~ ^[0-9a-fA-F]{64}`$ ]]; then printf '%s' "`$c"; else pbkdf2 "`$c"; fi ;;
    P) pbkdf2 "`$(read_pass)" ;;
    B) c=`$(read_key); p=`$(read_pass); pbkdf2 "`$p|`$c" ;;
    *) echo "[CODE-OBF] mode sconosciuto" >&2; exit 1 ;;
  esac
}
mk=`$(derive)
tmp=`$(mktemp); printf '%s%s' "`$iv" "`$ct" | xxd -r -p > "`$tmp"
calc=`$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"`$mk" -binary "`$tmp" | xxd -p -c999 | cut -c1-32)
rm -f "`$tmp"
[ "`$calc" = "`$tag" ] || { echo "[CODE-OBF] HMAC invalido" >&2; exit 1; }
ctlen=`$((`${#ct}/2)); blocks=`$(( (ctlen+31)/32 )); ks=""
for ((i=0;i<blocks;i++)); do
  ctr=`$(printf '%08x' `$i)
  blk=`$(printf '%s%s%s' "`$mk" "`$iv" "`$ctr" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c999)
  ks+="`$blk"
done
ks=`${ks:0:`$((ctlen*2))}
pt=""
for ((i=0;i<ctlen;i++)); do
  a=`$((16#`${ct:`$((i*2)):2})); b=`$((16#`${ks:`$((i*2)):2}))
  pt+=`$(printf '%02x' `$((a^b)))
done
eval "`$(printf '%s' "`$pt" | xxd -r -p)"
"@
}

# ============================================================================
# OBFUSCATE ONE FILE
# ============================================================================

function Invoke-ObfuscateFile([string]$srcPath, [string]$dstPath, [string]$authMode, [string]$keyFilePath, [string]$pass) {
    $srcName = Split-Path $srcPath -Leaf
    $ext = [System.IO.Path]::GetExtension($srcName).ToLower()
    $supported = @(".py",".js",".mjs",".ts",".ps1",".sh")
    if ($supported -notcontains $ext) {
        Write-Host "  SKIP: $srcName" -ForegroundColor DarkGray
        return
    }

    Write-Host "  ??' $srcName" -NoNewline

    # Salt per-file (PBKDF2), IV per-file (stream cipher)
    $salt = Get-RandomBytes 16
    $iv   = Get-RandomBytes 16

    # Derivazione master key
    $mk = Get-MasterKey -authMode $authMode -keyFilePath $keyFilePath -pass $pass -salt $salt

    # Encrypt
    $plaintext = [System.IO.File]::ReadAllBytes($srcPath)
    $ks        = Get-Keystream $mk $iv $plaintext.Length
    $ct        = Invoke-StreamXor $plaintext $ks

    # HMAC tag (16 bytes = 128-bit)
    $authBuf = New-Object byte[] ($iv.Length + $ct.Length)
    [Array]::Copy($iv, 0, $authBuf, 0, $iv.Length)
    [Array]::Copy($ct, 0, $authBuf, $iv.Length, $ct.Length)
    $fullTag = Get-HmacSha256 $mk $authBuf
    $tag = $fullTag[0..15]

    $saltHex = ConvertTo-HexString $salt
    $ivHex   = ConvertTo-HexString $iv
    $tagHex  = ConvertTo-HexString ([byte[]]$tag)
    $ctHex   = ConvertTo-HexString $ct

    # Mode char breve nel wrapper: K / P / B
    $modeCh = switch ($authMode) { "keyfile" {"K"} "password" {"P"} "both" {"B"} }

    $wrapper = switch ($ext) {
        ".py"  { New-PythonWrapper     $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
        ".js"  { New-JsWrapper         $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
        ".mjs" { New-JsWrapper         $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
        ".ts"  { New-TypeScriptWrapper $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
        ".ps1" { New-PowerShellWrapper $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
        ".sh"  { New-ShellWrapper      $modeCh $saltHex $ivHex $tagHex $ctHex $srcName $PBKDF2_ITER }
    }

    New-Item -ItemType Directory -Path (Split-Path $dstPath -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($dstPath, $wrapper, [System.Text.Encoding]::UTF8)

    $kb1 = [math]::Round($plaintext.Length / 1KB, 1)
    $kb2 = [math]::Round((Get-Item $dstPath).Length / 1KB, 1)
    Write-Host ("  OK  ({0} KB ??' {1} KB)" -f $kb1, $kb2) -ForegroundColor Green
}

# ============================================================================
# DEOBFUSCATE ONE FILE
# ============================================================================

function Invoke-DeobfuscateFile([string]$obfPath, [string]$outPath, [string]$keyFilePath, [string]$pass) {
    $content = [System.IO.File]::ReadAllText($obfPath, [System.Text.Encoding]::UTF8)
    if ($content -notmatch '\[CODE-OBF-META\]\s+mode=([KPB])\s+salt=([0-9a-f]+)\s+iv=([0-9a-f]+)\s+tag=([0-9a-f]+)\s+ct=([0-9a-f]+)') {
        Write-Host "  ERRORE: header [CODE-OBF-META] non trovato o formato v2 incompatibile." -ForegroundColor Red
        return $false
    }
    $modeCh = $Matches[1]
    $salt   = ConvertFrom-HexString $Matches[2]
    $iv     = ConvertFrom-HexString $Matches[3]
    $tag    = ConvertFrom-HexString $Matches[4]
    $ct     = ConvertFrom-HexString $Matches[5]

    $authMode = switch ($modeCh) { "K" {"keyfile"} "P" {"password"} "B" {"both"} }
    Write-Host "  Auth mode rilevato: $authMode" -ForegroundColor Cyan

    try {
        $mk = Get-MasterKey -authMode $authMode -keyFilePath $keyFilePath -pass $pass -salt $salt
    } catch {
        Write-Host "  ERRORE: $_" -ForegroundColor Red
        return $false
    }

    $authBuf = New-Object byte[] ($iv.Length + $ct.Length)
    [Array]::Copy($iv, 0, $authBuf, 0, $iv.Length)
    [Array]::Copy($ct, 0, $authBuf, $iv.Length, $ct.Length)
    $calc = (Get-HmacSha256 $mk $authBuf)[0..15]
    for ($i = 0; $i -lt 16; $i++) {
        if ($calc[$i] -ne $tag[$i]) {
            Write-Host "  ERRORE: HMAC invalido (credenziali sbagliate o file manomesso)." -ForegroundColor Red
            return $false
        }
    }

    $ks = Get-Keystream $mk $iv $ct.Length
    $pt = Invoke-StreamXor $ct $ks

    New-Item -ItemType Directory -Path (Split-Path $outPath -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($outPath, $pt)
    $kb = [math]::Round($pt.Length / 1KB, 1)
    Write-Host ("  Deofuscato: {0}  ({1} KB)" -f (Split-Path $outPath -Leaf), $kb) -ForegroundColor Green
    return $true
}

# ============================================================================
# MODE: DEOBFUSCATE
# ============================================================================

if ($Mode -eq "deobfuscate") {
    Write-Host "??"?????????????????????????????????????????? MODALIT??: DEOFUSCAZIONE ????????????????????????????????????????????-" -ForegroundColor Magenta
    Write-Host ""

    if (-not $FilePath) { $FilePath = (Read-Host "Path del file obfuscato").Trim('"').Trim("'") }
    if (-not (Test-Path $FilePath)) { Write-Host "File non trovato: $FilePath" -ForegroundColor Red; exit 1 }

    # Leggi header per capire auth mode richiesta
    $peek = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
    if ($peek -match '\[CODE-OBF-META\]\s+mode=([KPB])') {
        $detectedMode = switch ($Matches[1]) { "K" {"keyfile"} "P" {"password"} "B" {"both"} }
        Write-Host "Auth mode richiesto: $detectedMode" -ForegroundColor Cyan
    } else {
        Write-Host "File non riconosciuto come CODE-OBF v3." -ForegroundColor Red; exit 1
    }

    # Chiedi credenziali necessarie
    if ($detectedMode -in @("keyfile","both")) {
        if (-not $KeyFile) {
            if ($env:CODE_OBF_KEY) { $KeyFile = $env:CODE_OBF_KEY }
            else { $KeyFile = (Read-Host "Path del keyfile").Trim('"').Trim("'") }
        }
        if (-not (Test-Path $KeyFile)) { Write-Host "Keyfile non trovato: $KeyFile" -ForegroundColor Red; exit 1 }
    }
    if ($detectedMode -in @("password","both")) {
        if (-not $Password) {
            if ($env:CODE_OBF_PASS) { $Password = $env:CODE_OBF_PASS }
            else { $Password = Read-SecurePassword "Password" }
        }
    }

    $leaf     = Split-Path $FilePath -Leaf
    $ext      = [System.IO.Path]::GetExtension($leaf)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $outDir   = Split-Path $FilePath -Parent
    $outPath  = Join-Path $outDir ($baseName + ".deobf" + $ext)

    Write-Host ""
    Write-Host "File:     $FilePath" -ForegroundColor Yellow
    if ($KeyFile) { Write-Host "Keyfile:  $KeyFile" -ForegroundColor Yellow }
    Write-Host "Output:   $outPath" -ForegroundColor Yellow
    Write-Host ""

    if (Invoke-DeobfuscateFile $FilePath $outPath $KeyFile $Password) {
        Write-Host ""
        Write-Host "Deofuscazione completata: $outPath" -ForegroundColor Green
    }
    exit 0
}

# ============================================================================
# MODE: OBFUSCATE
# ============================================================================

Write-Host "??"?????????????????????????????????????????? MODALIT??: OBFUSCAZIONE ???????????????????????????????????????????????-" -ForegroundColor Cyan
Write-Host ""

# Se Auth non passato esplicitamente, chiedi
if (-not $PSBoundParameters.ContainsKey('Auth')) {
    Write-Host "Scegli il metodo di autenticazione:" -ForegroundColor Yellow
    Write-Host "  1) keyfile   - file .key (default, gira senza interazione)"
    Write-Host "  2) password  - password digitata/env (niente file da custodire)"
    Write-Host "  3) both      - keyfile + password (2FA, massima sicurezza)"
    $choice = Read-Host "Scelta [1/2/3]"
    switch ($choice) {
        "2" { $Auth = "password" }
        "3" { $Auth = "both" }
        default { $Auth = "keyfile" }
    }
}

Write-Host "Auth mode: $Auth" -ForegroundColor Cyan
Write-Host ""

if (-not $ProjectPath) {
    $ProjectPath = (Read-Host "PATH PROGETTO da obfuscare").Trim('"').Trim("'")
}
if (-not (Test-Path $ProjectPath)) { Write-Host "Cartella non trovata: $ProjectPath" -ForegroundColor Red; exit 1 }
$ProjectPath = (Resolve-Path $ProjectPath).Path

if (-not $OutputPath) {
    $defaultOut = Join-Path $ProjectPath "dist"
    Write-Host "Output path (Invio = $defaultOut):"
    $OutputPath = (Read-Host "OUTPUT PATH").Trim('"').Trim("'")
    if (-not $OutputPath) { $OutputPath = $defaultOut }
}

# Gestione credenziali a seconda dell'Auth mode
if ($Auth -in @("keyfile","both")) {
    if (-not $KeyFile) {
        $defaultKey = Join-Path (Split-Path $OutputPath -Parent) "code-obf.key"
        Write-Host ""
        Write-Host "KEYFILE path (Invio = $defaultKey):" -ForegroundColor Yellow
        Write-Host "  Se il file esiste gi??, verr?? riusato (pu?? contenere 64 hex random" -ForegroundColor DarkGray
        Write-Host "  OPPURE una password che scrivi tu dentro)." -ForegroundColor DarkGray
        Write-Host "  Se non esiste, ne genero uno con 64 hex random." -ForegroundColor DarkGray
        Write-Host "  *** NON metterlo dentro OutputPath, NON committarlo  ***" -ForegroundColor Red
        $KeyFile = (Read-Host "KEYFILE").Trim('"').Trim("'")
        if (-not $KeyFile) { $KeyFile = $defaultKey }
    }

    # In modalit?? 'keyfile'/'both': crea il file con hex random se non esiste.
    # Se l'utente vuole metterci una password, deve creare lui il file prima.
    if (-not (Test-Path $KeyFile)) {
        Write-Host ""
        Write-Host "Il keyfile non esiste. Vuoi:" -ForegroundColor Yellow
        Write-Host "  1) generare 64 hex random (raccomandato)"
        Write-Host "  2) annullare (cos?? lo crei tu con una password dentro)"
        $kc = Read-Host "Scelta [1/2]"
        if ($kc -eq "2") {
            Write-Host "Crea il file con la tua password, poi rilancia lo script." -ForegroundColor Cyan
            exit 0
        }
        Get-OrCreateKeyFile $KeyFile $true
    } else {
        Get-OrCreateKeyFile $KeyFile $false
    }
}

if ($Auth -in @("password","both")) {
    if (-not $Password) {
        if ($env:CODE_OBF_PASS) {
            $Password = $env:CODE_OBF_PASS
            Write-Host "Password presa da `$env:CODE_OBF_PASS" -ForegroundColor DarkGray
        } else {
            Write-Host ""
            $Password = Read-SecurePassword "Inserisci la password"
            $confirm  = Read-SecurePassword "Conferma password"
            if ($Password -ne $confirm) { Write-Host "Le password non coincidono." -ForegroundColor Red; exit 1 }
            if ($Password.Length -lt 8) { Write-Host "Password troppo corta (minimo 8 caratteri)." -ForegroundColor Red; exit 1 }
        }
    }
}

# Sanity: keyfile NON dentro OutputPath
if ($KeyFile) {
    $keyFull = [System.IO.Path]::GetFullPath($KeyFile)
    $outFull = [System.IO.Path]::GetFullPath($OutputPath)
    if ($keyFull.StartsWith($outFull, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host ""
        Write-Host "ATTENZIONE: il keyfile ?? DENTRO la cartella output!" -ForegroundColor Red
        $go = Read-Host "Continuo comunque? [s/N]"
        if ($go.ToLower() -ne "s") { exit 0 }
    }
}

Write-Host ""
Write-Host "?"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"?" -ForegroundColor DarkGray
Write-Host "Progetto:  $ProjectPath" -ForegroundColor White
Write-Host "Output:    $OutputPath" -ForegroundColor White
Write-Host "Auth:      $Auth" -ForegroundColor White
if ($KeyFile)  { Write-Host "Keyfile:   $KeyFile" -ForegroundColor White }
if ($Password) { Write-Host "Password:  (impostata)" -ForegroundColor White }
Write-Host "Crypto:    SHA256-CTR + HMAC-SHA256 + PBKDF2-$PBKDF2_ITER" -ForegroundColor White
Write-Host "?"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"??"?" -ForegroundColor DarkGray
Write-Host ""
$confirm = Read-Host "Procedo? [S/n]"
if ($confirm -and $confirm.ToLower() -eq "n") { Write-Host "Annullato."; exit 0 }

Write-Host ""
$excludeDirs = @(".venv","node_modules","dist",".git","__pycache__",".mypy_cache","build","bin","obj")
$supportedExt = @(".py",".js",".mjs",".ts",".ps1",".sh")

Write-Host "Scansione file..." -ForegroundColor Yellow
$srcFiles = Get-ChildItem -Path $ProjectPath -Recurse -File | Where-Object {
    $inExcluded = $false
    $parts = $_.FullName.Replace($ProjectPath,"").Split([IO.Path]::DirectorySeparatorChar)
    foreach ($p in $parts) { if ($excludeDirs -contains $p) { $inExcluded = $true; break } }
    -not $inExcluded -and ($supportedExt -contains $_.Extension.ToLower())
}
Write-Host "  Trovati $($srcFiles.Count) file" -ForegroundColor Cyan
Write-Host ""

$done = 0
foreach ($file in $srcFiles) {
    $rel     = $file.FullName.Substring($ProjectPath.Length).TrimStart('\','/')
    $dstPath = Join-Path $OutputPath $rel
    Invoke-ObfuscateFile $file.FullName $dstPath $Auth $KeyFile $Password
    if (Test-Path $dstPath) { $done++ }
}

Write-Host ""
Write-Host "?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????" -ForegroundColor Cyan
Write-Host "  Obfuscazione completata!  File: $done" -ForegroundColor Green
Write-Host "  Output:   $OutputPath" -ForegroundColor Cyan
if ($KeyFile) { Write-Host "  Keyfile:  $KeyFile" -ForegroundColor Yellow }
Write-Host "?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????" -ForegroundColor Cyan
Write-Host ""
Write-Host "PER ESEGUIRE i file obfuscati (auth=$Auth):" -ForegroundColor Magenta
switch ($Auth) {
    "keyfile" {
        Write-Host "  `$env:CODE_OBF_KEY = '$KeyFile'"
        Write-Host "  python dist\mio_programma.py"
    }
    "password" {
        Write-Host "  `$env:CODE_OBF_PASS = 'la-tua-password'   # oppure la digiti al prompt"
        Write-Host "  python dist\mio_programma.py"
    }
    "both" {
        Write-Host "  `$env:CODE_OBF_KEY  = '$KeyFile'"
        Write-Host "  `$env:CODE_OBF_PASS = 'la-tua-password'   # oppure la digiti al prompt"
        Write-Host "  python dist\mio_programma.py"
    }
}
Write-Host ""
Write-Host "PER DEOFUSCARE:" -ForegroundColor Magenta
Write-Host "  .\obfuscate.ps1 -Mode deobfuscate -FilePath <file>"
Write-Host "  (chiede keyfile/password in base al mode embedded nel file)"
Write-Host ""
