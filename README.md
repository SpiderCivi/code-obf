# CODE-OBF v3 — Obfuscator con Keyfile, Password o 2FA

Obfuscatore con **crittografia reale** (SHA256-CTR + HMAC-SHA256 + PBKDF2-200k). Tre modalità di autenticazione a scelta:

| Mode | Cosa serve per eseguire/deofuscare |
|---|---|
| **keyfile** | un file `.key` (custodito da te) |
| **password** | una password (nella tua testa o in variabile d'ambiente) |
| **both** (2FA) | keyfile **E** password (massima sicurezza) |

**Linguaggi supportati:** `.py` `.js` `.mjs` `.ts` `.ps1` `.sh`

---

## Partenza veloce (TL;DR)

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

## Indice

1. [Come OBFUSCARE un progetto](#come-obfuscare-un-progetto)
2. [Come ESEGUIRE i file obfuscati](#come-eseguire-i-file-obfuscati)
3. [Come DEOFUSCARE un file](#come-deofuscare-un-file)
4. [Quale modalità scegliere](#quale-modalità-scegliere)
5. [Il codice funziona ancora dopo l'obfuscazione?](#il-codice-funziona-ancora-dopo-lobfuscazione)
6. [Parametri CLI completi](#parametri-cli-completi)
7. [Come funziona (tecnico)](#come-funziona-tecnico)
8. [Requisiti](#requisiti)

---

## Come OBFUSCARE un progetto

### Modo interattivo (consigliato la prima volta)

```powershell
cd C:\Users\civie\Desktop\CODE-OBF
.\obfuscate.ps1
```

Lo script ti chiede in sequenza:

1. **Auth mode** → `1` keyfile, `2` password, `3` both
2. **PATH PROGETTO** → cartella sorgenti, es. `C:\Users\civie\Desktop\mio-progetto`
3. **OUTPUT PATH** → dove mettere i file cifrati (default: `PROGETTO\dist`)
4. **KEYFILE path** (se Auth = keyfile o both) → dove creare/trovare il file `.key`
5. **Password** (se Auth = password o both) → la digiti due volte per conferma

### Modo non-interattivo (per script / automazioni)

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

### Cosa produce

- I file `.py` `.js` `.mjs` `.ts` `.ps1` `.sh` della tua cartella diventano **wrapper cifrati** nella `dist/` (stessa struttura di sottocartelle)
- Il keyfile (se richiesto) viene creato dove hai indicato
- I file di config (`.env`, `.json`, `.yml`, `.sql`) restano **non obfuscati** (devono essere leggibili a runtime)
- Sorgenti originali: **intatti** (non vengono toccati)

### Regole d'oro per il keyfile / password

- **Keyfile**: NON metterlo dentro `dist/`, NON committarlo su git (`*.key` nel `.gitignore`), fanne backup
- **Password**: usane una lunga (12+ caratteri, mix lettere/numeri/simboli)
- Se perdi il keyfile E la password → **codice irrecuperabile per sempre**

---

## Come ESEGUIRE i file obfuscati

Il file obfuscato si decifra **da solo** in memoria all'avvio e parte come un programma normale. Deve solo poter leggere le credenziali (keyfile o password) da variabile d'ambiente o dal filesystem.

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

**Alternativa senza variabile**: copia il keyfile come `code-obf.key` nella cartella da cui lanci il programma (cwd), viene trovato automaticamente.

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

Se manca **anche uno solo** → errore `[CODE-OBF] HMAC invalido`.

---

## Come DEOFUSCARE un file

Deofuscare significa: prendere un file obfuscato e **ricreare il sorgente originale** su disco (senza eseguirlo). Utile per debug o recupero.

> ⚠️ **IMPORTANTE**: non puoi deofuscare il **keyfile stesso** — il keyfile è solo la chiave, non un file obfuscato. Deofusca solo file generati nella cartella `dist/`.

### Metodo consigliato — `deobf.ps1` (script dedicato)

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

Lo script **rileva automaticamente** l'auth mode dal file e chiede solo le credenziali necessarie. Produce `<nome>.deobf.<ext>` accanto al file originale.

### Metodo alternativo — via `obfuscate.ps1`

```powershell
.\obfuscate.ps1 -Mode deobfuscate `
                -FilePath "C:\Users\civie\Desktop\mio-progetto\dist\main.py" `
                -KeyFile  "C:\Users\civie\secrets\code-obf.key" `
                -Password "la-mia-password"
```

Lo script rileva **automaticamente** l'auth mode dal file e chiede solo le credenziali necessarie.

### Se la deofuscazione fallisce

- `HMAC invalido` → keyfile/password sbagliati, o il file è stato manomesso
- `File non riconosciuto` → stai deofuscando un file sbagliato (es. il keyfile stesso, o un file non prodotto da CODE-OBF)
- `Keyfile non trovato` → path sbagliato o file cancellato

---

## Quale modalità scegliere

**Keyfile (random)** — il codice gira da solo in automatico (cron, servizio, container) perché il keyfile è sempre lì. Rischio: se rubano il file, rubano tutto.

**Keyfile (password dentro)** — crei tu il file `.key` a mano scrivendoci una password invece dei 64 hex random. Lo script rileva che non è hex e applica PBKDF2 sulla password. Sicurezza = keyfile random.

**Password digitata** — niente file, solo la tua memoria. Ideale per codice che lanci **tu a mano**. Se il codice deve girare headless, usa la variabile `CODE_OBF_PASS`.

**Both (2FA)** — massima sicurezza, serve sia il file che la password. Usa questo per codice davvero critico.

---

## Il codice funziona ancora dopo l'obfuscazione?

**Sì, identico.** Il wrapper decifra il sorgente in memoria all'avvio, poi il programma gira come se non fosse mai stato obfuscato.

### Cosa funziona identico

- `import`, `require`, librerie esterne
- File di config esterni (`.env`, `.json`, `.yml`, `.sql`)
- Argomenti CLI (`sys.argv`, `process.argv`, `$args`)
- Variabili d'ambiente, filesystem, rete, database
- `if __name__ == "__main__"` in Python

### Limitazioni note

| Situazione | Problema | Soluzione |
|---|---|---|
| Linter / debugger / coverage | Vedono il wrapper, non il sorgente | Usa i sorgenti originali in dev |
| TypeScript type-checking | Il wrapper fa `new Function()`, tipi non verificati | Compila `.ts` → `.js` con `tsc`, poi obfusca |
| `__file__` in Python | Punta al wrapper | Usa `os.path.dirname(sys.argv[0])` |
| Node + password/both | Niente prompt sincrono senza deps | Usa `CODE_OBF_PASS` (env var) |
| Bash grosso (>100 KB) | XOR in bash puro è lento | Riscrivi in Python |
| Codice usato come libreria importata | `exec` nel namespace del wrapper | Per librerie, obfusca solo entry-point |

### Performance

- **Avvio**: ~0.1-0.5s (PBKDF2 200k iter + decrypt), trascurabile per programmi che girano secondi/minuti
- **Runtime**: zero overhead dopo l'avvio

---

## Parametri CLI completi

### `obfuscate.ps1`

| Parametro | Default | Descrizione |
|---|---|---|
| `-Mode` | `obfuscate` | `obfuscate` o `deobfuscate` |
| `-Auth` | *(chiede)* | `keyfile` / `password` / `both` |
| `-ProjectPath` | *(chiede)* | Cartella sorgenti da obfuscare |
| `-OutputPath` | `ProjectPath\dist` | Destinazione wrapper |
| `-KeyFile` | *(chiede)* | Path del `.key` |
| `-Password` | *(chiede)* | Password (sconsigliato in CLI, usa env var) |
| `-FilePath` | *(chiede)* | In `deobfuscate`: file da decifrare |

### `deobf.ps1` (deobfuscator standalone)

| Parametro | Default | Descrizione |
|---|---|---|
| `-FilePath` | *(chiede)* | File obfuscato da decifrare |
| `-KeyFile` | *(chiede se serve)* | Path del `.key` (solo per auth K/B) |
| `-Password` | *(chiede se serve)* | Password (solo per auth P/B) |

Lo script legge l'auth mode dall'header del file e chiede solo le credenziali necessarie.

### Variabili d'ambiente

| Variabile | Ruolo |
|---|---|
| `CODE_OBF_KEY` | Path del keyfile (a runtime, per auth K e B) |
| `CODE_OBF_PASS` | Password (a runtime, per auth P e B; obbligatoria per Node/JS/TS) |

---

## Cosa viene obfuscato / ignorato

| Obfuscato | Ignorato |
|---|---|
| `.py` `.js` `.mjs` `.ts` `.ps1` `.sh` | `.venv` `node_modules` `dist` `.git` `__pycache__` `.mypy_cache` `build` `bin` `obj` |
| Tutte le sottocartelle | File config (`.env`, `.yml`, `.json`, `.sql`, ecc.) |

---

## Come funziona (tecnico)

### Schema crittografico

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

### Formato wrapper (metadata riga singola)

```
<comment> [CODE-OBF v3] <nomeFile> | auth=<K|P|B> | SHA256-CTR + HMAC + PBKDF2
<comment> [CODE-OBF-META] mode=<K|P|B> salt=<32hex> iv=<32hex> tag=<32hex> ct=<Nhex>
<decoder nel linguaggio originale>
```

### Perché è sicuro

- **Chiave non nel file**: senza keyfile/password un attaccante ha solo `salt`, `iv`, `ct`, `tag` — niente scorciatoie
- **Bruteforce password**: PBKDF2 200k iter → ~100ms per tentativo → password robusta infattibile
- **Bruteforce chiave**: 2²⁵⁶ tentativi → termodinamicamente impossibile
- **Tamper detection**: HMAC rileva qualsiasi modifica al ciphertext
- **Salt per-file**: rainbow tables inutili

### Limite onesto

Se un attaccante ha accesso alla macchina **mentre il codice è in esecuzione**, può dumpare la memoria. È un limite generale di tutti gli obfuscator software. Per protezione runtime serve hardware (TEE, enclave).

---

## Requisiti

**Lato obfuscator (solo tu):**
- Windows 10/11 con PowerShell 5.1+

**Lato esecuzione (chi esegue i file obfuscati):**

| Linguaggio | Runtime | Note |
|---|---|---|
| `.py` | Python 3 | `hashlib`, `hmac`, `getpass` sono stdlib |
| `.js` / `.mjs` | Node.js 14+ | `crypto` built-in; password via `CODE_OBF_PASS` |
| `.ts` | Node + ts-node | stesso vincolo di JS |
| `.ps1` | PowerShell 5.1+ | stdlib .NET |
| `.sh` | bash + `openssl` + `xxd` + `python3` | `python3` usato solo per PBKDF2 |

```powershell
# Se PowerShell blocca lo script
Set-ExecutionPolicy -Scope Process Bypass
```
