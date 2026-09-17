# CODE-OBF v3 — Obfuscator with Keyfile, Password, or 2FA

Obfuscator with **real encryption** (SHA256-CTR + HMAC-SHA256 + PBKDF2-200k). Three authentication modes to choose from:

| Mode | What you need to run/deobfuscate |
|---|---|
| **keyfile** | a `.key` file (kept safe by you) |
| **password** | a password (in your head or in an environment variable) |
| **both** (2FA) | keyfile **AND** password (maximum security) |

**Supported languages:** `.py` `.js` `.mjs` `.ts` `.ps1` `.sh`

---

## Quick start (TL;DR)

```powershell
# 1. OBFUSCA un progetto
cd C:\Users\civie\Desktop\CODE-OBF
.\obfuscate.ps1

#    Rispondi alle domande:
#    - Auth mode: 1 (keyfile) | 2 (password) | 3 (both)
#    - PATH PROGETTO: C:\Users\civie\Desktop\mio-progetto
#    - OUTPUT PATH: Invio (default: mio-progetto\dist)
#    - KEYFILE: Invio (default: sopra la dist)
#    - Password: la digiti se hai scelto 2 o 3

# 2. ESEGUI un file obfuscato
$env:CODE_OBF_KEY = "C:\Users\civie\secrets\code-obf.key"
python C:\Users\civie\Desktop\mio-progetto\dist\main.py

# 3. DEOFUSCA (recupera il sorgente originale)
.\deobf.ps1 -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.js" `
            -KeyFile  "C:\Users\civie\Desktop\code-obf.key"
# Produce main.deobf.js accanto al file
```

---

## Table of Contents

1. [How to OBFUSCATE a project](#how-to-obfuscate-a-project)
2. [How to RUN obfuscated files](#how-to-run-obfuscated-files)
3. [How to DEOBFUSCATE a file](#how-to-deobfuscate-a-file)
4. [Which mode to choose](#which-mode-to-choose)
5. [Does the code still work after obfuscation?](#does-the-code-still-work-after-obfuscation)
6. [Full CLI parameters](#full-cli-parameters)
7. [How it works (technical)](#how-it-works-technical)
8. [Requirements](#requirements)

---

## How to OBFUSCATE a project

### Interactive mode (recommended for the first time)

```powershell
cd C:\Users\civie\Desktop\CODE-OBF
.\obfuscate.ps1
```

The script asks you, in sequence:

1. **Auth mode** → `1` keyfile, `2` password, `3` both
2. **PROJECT PATH** → source folder, e.g. `C:\Users\civie\Desktop\mio-progetto`
3. **OUTPUT PATH** → where to put the encrypted files (default: `PROGETTO\dist`)
4. **KEYFILE path** (if Auth = keyfile or both) → where to create/find the `.key` file
5. **Password** (if Auth = password or both) → you type it twice to confirm

### Non-interactive mode (for scripts / automation)

```powershell
# Auth keyfile (random)
.\obfuscate.ps1 -Auth keyfile `
                -ProjectPath "C:\Users\civie\Desktop\mio-progetto" `
                -OutputPath  "C:\Users\civie\Desktop\mio-progetto\dist" `
                -KeyFile     "C:\Users\civie\secrets\code-obf.key"

# Auth password (digitata / env)
$env:CODE_OBF_PASS = "la-mia-password-lunga"
.\obfuscate.ps1 -Auth password `
                -ProjectPath "C:\Users\civie\Desktop\mio-progetto"

# Auth both (2FA)
$env:CODE_OBF_PASS = "la-mia-password-lunga"
.\obfuscate.ps1 -Auth both `
                -ProjectPath "C:\Users\civie\Desktop\mio-progetto" `
                -KeyFile     "C:\Users\civie\secrets\code-obf.key"
```

### What it produces

- The `.py` `.js` `.mjs` `.ts` `.ps1` `.sh` files in your folder become **encrypted wrappers** in `dist/` (same subfolder structure)
- The keyfile (if required) is created where you specified
- Config files (`.env`, `.json`, `.yml`, `.sql`) remain **non-obfuscated** (they must be readable at runtime)
- Original sources: **intact** (not touched)

### Golden rules for the keyfile / password

- **Keyfile**: do NOT put it inside `dist/`, do NOT commit it to git (`*.key` in `.gitignore`), back it up
- **Password**: use a long one (12+ characters, mix of letters/numbers/symbols)
- If you lose the keyfile AND the password → **code unrecoverable forever**

---

## How to RUN obfuscated files

The obfuscated file decrypts **itself** in memory at startup and runs as a normal program. It only needs to be able to read the credentials (keyfile or password) from an environment variable or from the filesystem.

### Auth = keyfile

```powershell
# Windows / PowerShell
$env:CODE_OBF_KEY = "C:\Users\civie\secrets\code-obf.key"
python dist\main.py
node dist\server.mjs
.\dist\deploy.ps1
```

```bash
# Linux / Mac / WSL
export CODE_OBF_KEY="/path/sicuro/code-obf.key"
python3 dist/main.py
node dist/server.mjs
bash dist/deploy.sh
```

**Alternative without an environment variable**: copy the keyfile as `code-obf.key` into the folder you launch the program from (cwd); it will be found automatically.

### Auth = password

```powershell
# A) interattivo (Python/PS/bash chiedono la password al prompt)
python dist\main.py
# [CODE-OBF] password: _____

# B) via variabile (obbligatorio per Node/JS/TS)
$env:CODE_OBF_PASS = "la-mia-password-lunga"
python dist\main.py
```

### Auth = both

```powershell
$env:CODE_OBF_KEY  = "C:\Users\civie\secrets\code-obf.key"
$env:CODE_OBF_PASS = "la-mia-password-lunga"
python dist\main.py
```

If even one of them is missing → error `[CODE-OBF] HMAC invalido`.

---

## How to DEOBFUSCATE a file

Deobfuscating means: taking an obfuscated file and **recreating the original source** on disk (without executing it). Useful for debugging or recovery.

> ⚠️ **IMPORTANT**: you cannot deobfuscate the **keyfile itself** — the keyfile is only the key, not an obfuscated file. Only deobfuscate files generated in the `dist/` folder.

### Recommended method — `deobf.ps1` (dedicated script)

```powershell
# Auth = keyfile
.\deobf.ps1 -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py" `
            -KeyFile  "C:\Users\civie\secrets\code-obf.key"

# Auth = password (interattivo: chiede la password al prompt)
.\deobf.ps1 -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py"

# Auth = password (non-interattivo via env)
$env:CODE_OBF_PASS = "la-mia-password"
.\deobf.ps1 -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py"

# Auth = both
.\deobf.ps1 -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py" `
            -KeyFile  "C:\Users\civie\secrets\code-obf.key" `
            -Password "la-mia-password"

# Modo completamente interattivo (chiede tutto)
.\deobf.ps1
```

The script **automatically detects** the auth mode from the file and only asks for the necessary credentials. It produces `<nome>.deobf.<ext>` next to the original file.

### Alternative method — via `obfuscate.ps1`

```powershell
.\obfuscate.ps1 -Mode deobfuscate `
                -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py" `
                -KeyFile  "C:\Users\civie\secrets\code-obf.key" `
                -Password "la-mia-password"
```

The script **automatically** detects the auth mode from the file and only asks for the necessary credentials.

### If deobfuscation fails

- `HMAC invalido` → wrong keyfile/password, or the file has been tampered with
- `File non riconosciuto` → you're deobfuscating the wrong file (e.g. the keyfile itself, or a file not produced by CODE-OBF)
- `Keyfile non trovato` → wrong path or file deleted

---

## Which mode to choose

**Keyfile (random)** — the code runs automatically on its own (cron, service, container) because the keyfile is always there. Risk: if someone steals the file, they steal everything.

**Keyfile (password inside)** — you create the `.key` file by hand, writing a password into it instead of 64 random hex characters. The script detects that it's not hex and applies PBKDF2 to the password. Security = random keyfile.

**Typed password** — no file, just your memory. Ideal for code that **you launch by hand**. If the code needs to run headless, use the `CODE_OBF_PASS` variable.

**Both (2FA)** — maximum security, requires both the file and the password. Use this for truly critical code.

---

## Does the code still work after obfuscation?

**Yes, identically.** The wrapper decrypts the source in memory at startup, then the program runs as if it had never been obfuscated.

### What works identically

- `import`, `require`, external libraries
- External config files (`.env`, `.json`, `.yml`, `.sql`)
- CLI arguments (`sys.argv`, `process.argv`, `$args`)
- Environment variables, filesystem, network, database
- `if __name__ == "__main__"` in Python

### Known limitations

| Situation | Problem | Solution |
|---|---|---|
| Linter / debugger / coverage | They see the wrapper, not the source | Use the original sources in dev |
| TypeScript type-checking | The wrapper does `new Function()`, types not verified | Compile `.ts` → `.js` with `tsc`, then obfuscate |
| `__file__` in Python | Points to the wrapper | Use `os.path.dirname(sys.argv[0])` |
| Node + password/both | No synchronous prompt without deps | Use `CODE_OBF_PASS` (env var) |
| Large Bash (>100 KB) | XOR in pure bash is slow | Rewrite in Python |
| Code used as an imported library | `exec` in the wrapper's namespace | For libraries, only obfuscate the entry point |

### Performance

- **Startup**: ~0.1-0.5s (PBKDF2 200k iter + decrypt), negligible for programs that run for seconds/minutes
- **Runtime**: zero overhead after startup

---

## Full CLI parameters

### `obfuscate.ps1`

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `obfuscate` | `obfuscate` or `deobfuscate` |
| `-Auth` | *(prompts)* | `keyfile` / `password` / `both` |
| `-ProjectPath` | *(prompts)* | Source folder to obfuscate |
| `-OutputPath` | `ProjectPath\dist` | Wrapper destination |
| `-KeyFile` | *(prompts)* | Path of the `.key` |
| `-Password` | *(prompts)* | Password (not recommended in CLI, use env var) |
| `-FilePath` | *(prompts)* | In `deobfuscate`: file to decrypt |

### `deobf.ps1` (standalone deobfuscator)

| Parameter | Default | Description |
|---|---|---|
| `-FilePath` | *(prompts)* | Obfuscated file to decrypt |
| `-KeyFile` | *(prompts if needed)* | Path of the `.key` (only for auth K/B) |
| `-Password` | *(prompts if needed)* | Password (only for auth P/B) |

The script reads the auth mode from the file's header and only asks for the necessary credentials.

### Environment variables

| Variable | Role |
|---|---|
| `CODE_OBF_KEY` | Path of the keyfile (at runtime, for auth K and B) |
| `CODE_OBF_PASS` | Password (at runtime, for auth P and B; mandatory for Node/JS/TS) |

---

## What gets obfuscated / ignored

| Obfuscated | Ignored |
|---|---|
| `.py` `.js` `.mjs` `.ts` `.ps1` `.sh` | `.venv` `node_modules` `dist` `.git` `__pycache__` `.mypy_cache` `build` `bin` `obj` |
| All subfolders | Config files (`.env`, `.yml`, `.json`, `.sql`, etc.) |

---

## How it works (technical)

### Cryptographic scheme

```
salt         = 16 bytes random (per-file, embedded nel wrapper)
iv           = 16 bytes random (per-file, embedded nel wrapper)

masterKey    = PBKDF2-HMAC-SHA256(secret, salt, 200000, 32)
  dove 'secret' dipende dal mode:
    K (keyfile):
      keyfile = 64 hex chars  → masterKey = bytes.fromhex(keyfile)  (no PBKDF2)
      keyfile = altro testo   → masterKey = PBKDF2(content, salt)
    P (password):
      masterKey = PBKDF2(password, salt)
    B (both):
      masterKey = PBKDF2(password + "|" + keyfile_content, salt)

keystream_i  = SHA256(masterKey || iv || BigEndian32(i))   per ogni blocco 32B
ciphertext   = plaintext XOR keystream
tag          = HMAC-SHA256(masterKey, iv || ciphertext)[:16]
```

### Wrapper format (single-line metadata)

```
<comment> [CODE-OBF v3] <nomeFile> | auth=<K|P|B> | SHA256-CTR + HMAC + PBKDF2
<comment> [CODE-OBF-META] mode=<K|P|B> salt=<32hex> iv=<32hex> tag=<32hex> ct=<Nhex>
<decoder nel linguaggio originale>
```

### Why it's secure

- **Key not in the file**: without the keyfile/password an attacker only has `salt`, `iv`, `ct`, `tag` — no shortcuts
- **Password bruteforce**: PBKDF2 200k iter → ~100ms per attempt → a strong password is infeasible to crack
- **Key bruteforce**: 2²⁵⁶ attempts → thermodynamically impossible
- **Tamper detection**: HMAC detects any modification to the ciphertext
- **Per-file salt**: rainbow tables useless

### An honest limitation

If an attacker has access to the machine **while the code is running**, they can dump the memory. This is a general limitation of all software obfuscators. Runtime protection requires hardware (TEE, enclave).

---

## Requirements

**On the obfuscator side (only you):**
- Windows 10/11 with PowerShell 5.1+

**On the execution side (whoever runs the obfuscated files):**

| Language | Runtime | Notes |
|---|---|---|
| `.py` | Python 3 | `hashlib`, `hmac`, `getpass` are stdlib |
| `.js` / `.mjs` | Node.js 14+ | `crypto` built-in; password via `CODE_OBF_PASS` |
| `.ts` | Node + ts-node | same constraint as JS |
| `.ps1` | PowerShell 5.1+ | .NET stdlib |
| `.sh` | bash + `openssl` + `xxd` + `python3` | `python3` used only for PBKDF2 |

```powershell
# Se PowerShell blocca lo script
Set-ExecutionPolicy -Scope Process Bypass
```
