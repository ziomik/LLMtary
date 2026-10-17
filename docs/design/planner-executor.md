# LLMtary — Planner-Executor e libreria azioni tipizzate (nota di design)

Engineer, 17/10/2026. Nota PRIMA del codice (assignment aa7c8d8d, parte 4; copre anche la parte 2b — stato strutturato tra iterazioni — perché il planner-executor È la riprogettazione a stato).

## 1. Problema

Oggi i loop (recon_service, exploit_executor) chiedono all'LLM un **comando in testo libero** per iterazione, lo eseguono, leggono l'output, richiedono il prossimo. Due difetti:
- **Hallucination**: il modello inventa path di modulo / opzioni / tool inesistenti (stessa famiglia dei bug nmap/CVE/Metasploit). Un 14B locale è particolarmente esposto.
- **Stato implicito**: ogni iterazione ricostruisce il contesto dal testo accumulato (history), senza uno stato tipizzato di «cosa ho osservato / provato / confermato». Costoso, fragile, e rende impossibile un auto-tuning o un dedup affidabile dello sforzo.

Le parti 1-3 già fatte/pianificate puntellano i bordi (schema JSON esatto per gli output; metriche per-comando; auto-tuning soglie). La parte 4 affronta la radice: **vincolare lo spazio d'azione** e **rendere lo stato esplicito**.

## 2. Proposta: planner → executor, con azioni tipizzate

Separare la **decisione** (planner) dall'**esecuzione** (executor), con una libreria chiusa di **azioni tipizzate**.

### 2.1 Libreria di azioni tipizzate (`lib/services/actions/`)
Un insieme CHIUSO di tipi d'azione, ognuno con parametri tipizzati e un JSON schema (riuso del meccanismo della parte 1). Bozza iniziale:
- `ReconScan { target, profile: quick|full|udp|script, ports? }`
- `ServiceProbe { target, port, kind: http|tls|smb|dns|ssh|… }`
- `SearchExploit { product, version?, cve? }` → ricerca REALE (searchsploit/msf), grounding
- `ExploitAttempt { moduleOrTool, params: Map, target, port }` → il modulo/tool va SCELTO da una lista reale, mai inventato
- `VerifyFinding { findingId, method: curl|session|manual, evidenceExpected }`
- `PostExploit { sessionRef, action: whoami|loot|pivot, args? }`
- `Conclude { reason, status }`

Ogni azione è un `sealed`/`abstract` con `toSchema()` e `fromJson()`. L'insieme è versionato.

### 2.2 Planner
Dato lo **stato tipizzato di sessione** (§2.4) e l'obiettivo, il planner emette **la prossima azione tipizzata** scegliendo da `availableActions` — una **scelta vincolata** (JSON schema con `enum` dei tipi d'azione + schema dei parametri), non testo libero. Per le azioni con identificatori (moduli, path), i valori ammessi vengono da una **ricerca reale** (es. `SearchExploit` prima di `ExploitAttempt`), così il modello sceglie da candidati esistenti invece di inventare.

### 2.3 Executor
Mappa l'azione tipizzata → comando/i concreti in modo **deterministico** (template per tipo+tool), poi esegue via l'infrastruttura esistente (`command_executor`: watchdog idle, repetition/output cap, kill-tree, metriche della parte 2a) e restituisce un **osservazione tipizzata** (non solo testo): esito, parsing specifico per tipo (porte aperte, servizio, prova trovata, sessione aperta…).

### 2.4 Stato strutturato di sessione (parte 2b)
Un oggetto tipizzato portato tra le iterazioni, invece di ri-derivare dal testo:
```
SessionState {
  target, goal,
  observations: List<Observation>,        // tipizzate per tipo d'azione
  findings: List<Vulnerability>,           // già tipizzate
  triedActions: List<{action, outcome}>,   // per dedup sforzo (classifyApproach già esiste)
  openQuestions: List<String>,
  sessions: List<SessionRef>,              // sessioni/accessi ottenuti
}
```
Il planner riceve lo stato, non il muro di testo; l'executor lo aggiorna con l'osservazione tipizzata. Questo rende naturale il dedup dello sforzo (riuso `CommandUtils.classifyApproach`/`isApproachExhausted`) e abilita l'auto-tuning (parte 3) con dati puliti.

## 3. Perché riduce l'hallucination
- Spazio d'azione **chiuso ed enumerato** (il modello sceglie un tipo, non inventa una riga di shell).
- Identificatori **grounded** da ricerche reali (moduli/path/CVE da liste esistenti).
- Output **vincolati** dallo schema esatto (parte 1).
- Lo stato tipizzato evita che il modello «dimentichi» e ritenti ciò che ha già provato.

## 4. Integrazione e rollout (incrementale, dietro flag)
- **Non** riscrivere i loop in un colpo. Introdurre planner-executor **dietro un flag** (settings) per un sottoinsieme: iniziare da **recon** (azioni poche e ben definite: ReconScan, ServiceProbe), poi exploit.
- **Fallback**: se il planner non sa mappare l'obiettivo in un'azione tipizzata, ricade sul percorso testo-libero attuale (nessuna regressione).
- L'executor **riusa** `command_executor` (watchdog/metriche/kill-tree) e `command_validator`; niente duplicazione.
- I template comando-per-azione-per-tool sono dati/config (estendibili come le fonti), non logica cablata.

## 5. Rapporto con le parti 1-3
- **Parte 1 (schemi)**: l'output del planner È un'azione tipizzata con schema → stesso meccanismo `responseSchema`.
- **Parte 2a (metriche)**: l'executor già emette `command_metrics.jsonl` per comando.
- **Parte 3 (auto-tuning)**: soglie per-tool dalle metriche; l'executor le applica per tipo d'azione/tool.

## 6. Rischi / domande aperte (per Satoshi/Mirko)
- **Copertura vs flessibilità**: una libreria d'azioni troppo stretta limita la creatività del pentest; troppo larga non vincola. Proposta: partire stretti su recon (dove l'hallucination fa più danni e lo spazio è piccolo) + fallback testo-libero per il resto.
- **Chi definisce i template comando per azione/tool**: config dati (come le fonti) rivista, non codice.
- **Schema dello stato**: va versionato e persistito? (per riprendere sessioni). Proposta: in memoria per v1, persistenza come follow-up.
- **Compatibilità**: il flag spento = comportamento attuale identico.
- **Ordine**: consiglio parte 3 (auto-tuning, isolata) PRIMA della 4, e la 4 incrementale partendo da recon.

## 7. Stima e primo passo
Primo passo a basso rischio (dopo l'ok al design): definire `actions/` + gli schemi (nessun cambio ai loop), più un `PlannerResult` tipizzato e un executor per **sole** `ReconScan`/`ServiceProbe` dietro flag, con fallback. Misurabile (hallucination rate recon prima/dopo sui log), reversibile.
