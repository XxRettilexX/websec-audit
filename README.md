# websec-audit

Strumento CLI in Python per eseguire **audit di sicurezza su siti web di tua proprietà** (o su cui hai
autorizzazione scritta a testare). Pensato per capire la postura di sicurezza di un sito e, soprattutto,
per capire **come correggere** i problemi trovati: ogni finding include una spiegazione e una remediation
concreta (con riferimenti OWASP dove applicabile).

## ⚠️ Uso autorizzato — leggi prima di usarlo

- Usa questo strumento **solo** su domini che possiedi o per cui hai un'autorizzazione scritta esplicita
  (pentest engagement, bug bounty in scope). Testare siti di terzi senza autorizzazione è **reato** in
  quasi tutte le giurisdizioni (in Italia: art. 615-ter c.p. e normative collegate).
- La modalità `active` genera traffico reale verso il target (richieste HTTP multiple, payload di
  rilevamento). Non esegue mai operazioni distruttive (no DROP/DELETE, no modifica dati, no DoS/flood),
  ma **va comunque eseguita solo con consapevolezza e autorizzazione**.
- Lo strumento impone un rate limit di default e richiede una conferma esplicita per abilitare la
  modalità `active`, per target.

## Cosa fa

### Modalità `passive` (sempre sicura, read-only, bassissimo volume di richieste)

| Check | Cosa verifica |
|---|---|
| `headers` | Header di sicurezza HTTP: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection deprecato |
| `cookies` | Flag `Secure`, `HttpOnly`, `SameSite` sui cookie di sessione |
| `tls` | Versione protocollo TLS, scadenza certificato, catena, cipher deboli |
| `cors` | Misconfigurazioni CORS (reflected `Origin` + `Access-Control-Allow-Credentials: true`) |
| `dns` | Record DNS (A/AAAA/MX/TXT/NS), presenza SPF/DMARC, sottodomini comuni esposti |
| `info_disclosure` | File/endpoint sensibili esposti in lettura (`.git/config`, `.env`, `server-status`, banner di versione nei header) |

### Modalità `active` (richiede `--active` + conferma esplicita per ogni target)

| Check | Cosa verifica |
|---|---|
| `injection` | Rilevamento (non distruttivo) di SQL injection ed XSS riflesso sui parametri GET presenti nell'URL target, tramite marker univoci e pattern di errore noti |
| `open_redirect` | Parametri comuni di redirect (`next`, `url`, `redirect`, `return`) che reindirizzano senza validazione verso un host esterno di test |
| `bruteforce_paths` | Ricerca read-only di path/file sensibili comuni (estensione della lista passiva, più ampia) |

Tutte le richieste attive sono rate-limited e usano solo GET/OPTIONS in lettura: nessun payload tenta di
modificare o esfiltrare dati reali.

## Installazione

```bash
cd websec-audit
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

Audit passivo su un singolo sito (sempre permesso, nessuna conferma richiesta):

```bash
python -m websec_audit --url https://tuosito.it
```

Audit attivo (richiede autorizzazione esplicita):

```bash
python -m websec_audit --url "https://tuosito.it/pagina?id=1" \
  --active --i-own-this-target --output report.md
```

Audit su più target da file di configurazione:

```bash
python -m websec_audit --config targets.yaml --output report.json --format json
```

Esempio `targets.yaml`:

```yaml
targets:
  - url: https://tuosito.it
    authorized: true
    mode: passive
  - url: "https://tuosito.it/search?q=test"
    authorized: true
    mode: active
```

`authorized: true` deve essere impostato esplicitamente dall'utente per ogni target in modalità `active`;
senza questo campo (o con `--config` che non lo imposta) lo strumento si ferma e chiede conferma.

## Output

Report in Markdown (default) o JSON, con per ogni finding: titolo, severità (`critical`/`high`/`medium`/
`low`/`info`), evidenza raccolta, e remediation.

## Struttura del progetto

```
websec_audit/
  cli.py              entry point CLI
  config.py            caricamento target da CLI/YAML
  http_client.py        client HTTP con rate limiting e User-Agent dedicato
  report.py             aggregazione e rendering del report
  remediation.py        testi di remediation/OWASP per ogni check
  checks/
    headers.py
    cookies.py
    tls.py
    cors.py
    dns_recon.py
    info_disclosure.py
    active_injection.py
    active_redirect.py
    active_bruteforce.py
tests/                  test unitari (pytest)
```

## Licenza

MIT. Vedi [LICENSE](LICENSE). Nessuna garanzia: usalo in modo responsabile e solo su target autorizzati.
