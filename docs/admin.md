# Admin page — users, verdict weights and thresholds

The **Admin** page (header → **Admin**, or `/admin`) controls how IntelChecker turns the raw answers of each CTI source into the two scores shown on every lookup — the **Knowledge Score** and the **Risk Score** — and into the **quadrant** label shown under them.

Nothing on this page changes *which* sources are queried or *what* they return. It only changes how much each answer counts.

> **Admins only.** The Admin page and the weights API are restricted to users with the **Admin** role. See [§ 0](#0-users-and-roles) for user management.

---

## 0. Users and roles

Every page and API call requires signing in. There are three roles:

| Role | Run lookups | Browse History | Edit weights · manage users |
|---|:-:|:-:|:-:|
| **Admin** | ✅ | ✅ | ✅ |
| **Analyst** | ✅ | ✅ | — |
| **Reader** | — | ✅ | — |

Readers don't see the home page search: they land on History. Every new History entry records the user who ran it.

**First admin.** On the very first start (no users yet) the backend creates an admin from `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `backend/.env` (username defaults to `admin`). If `ADMIN_PASSWORD` is empty, the password is **`admin`**, so a fresh deployment signs in with `admin` / `admin`. It isn't forced to change, but a warning is shown on every page until the password is changed (**My account**) — do it before going to production. Those variables are ignored once any user exists.

**Users** page (header → **Users**, or `/users` — only visible to admins):

- **Create user** — username, temporary password (≥ 8 characters) and role. The user must choose their own password on first sign-in.
- **Role** — change it from the drop-down; it applies on the user's next request.
- **Reset password** (key icon) — sets a new temporary password and signs the user out everywhere.
- **Disable / Enable** (power icon) — a disabled user can't sign in and is signed out immediately. Their history stays.
- **Delete** — removes the account; their past lookups stay in History with their name.
- Safeguards: there is always at least one active admin, and you can't change your own role, disable or delete yourself.

- **API tokens** (key-card button, with the number of active tokens) — create a token for scripts and integrations (name + expiry), list the user's tokens with their last use, and revoke them. The full token is shown **once**. A token acts as its user with the user's current role and stops working if the user is disabled or deleted; resetting the password doesn't revoke it. Usage: [api.md](api.md).

Any user can change their own password from **My account** (their name in the header); doing so signs out their other sessions.

**Sessions** last `SESSION_TTL_HOURS` (default 12) and live in an HttpOnly, SameSite=Strict cookie. When serving over HTTPS set `SESSION_COOKIE_SECURE=true`. After 5 failed sign-ins in 15 minutes an account rejects further attempts until the window passes. Users, password hashes (scrypt) and sessions are stored in `backend/data/users.db`.

**Locked out?** If no admin can sign in, stop the stack, delete `backend/data/users.db` (history and weights are untouched) and start it again: the first-admin bootstrap runs again.

### Connectors (API keys, MISP and OpenCTI)

**Connectors** page (header → **Connectors**, or `/connectors` — only visible to admins):

- **Layout** — one table per section (API keys, MISP, OpenCTI) with the columns *Source · Status · Key · Actions*, filter tabs with counts (**All / Configured / Not configured / Keyless**) and **Test all**, which tests every testable connector in view after confirming how many real requests it will send. Each row has two fixed action columns: the key (**Set key** or **Replace key**; **Complete** or **Edit** for MISP) and **Test**. The editor opens under the row with the `.env` variable name, a **Get a key** link and **Remove** (or **Delete** for a MISP instance). The editor shows two fields: **Current key** (masked, the eye reveals it) and **New key**. Test results also open under the row.
- **API keys** — one row per key, with the types it supports or the sources it powers (the abuse.ch key serves ThreatFox, URLhaus and MalwareBazaar). **Set key / Replace** saves it; **Remove** deletes the value saved here. Status: *Configured* (saved here), *From .env* (only in `backend/.env`) or *Not configured*. A key saved here wins over `.env`; removing it falls back to the `.env` value, if any.
- **MISP instances** — **Add instance** (name, URL, API key, *Verify TLS certificate*, optional mTLS client certificate / key chosen from the files in `backend/certs/`), **Edit** (leave the key empty to keep it) and **Delete**, inside the editor. Each instance is its own source; set its weights on the Admin page (new ones start at 0 / 9). Instances from `MISP_<N>_*` in `.env` are shown until the first MISP change here, which copies them over; from then on those variables are ignored.
- **OpenCTI instances** — the same table, form and rules as MISP (name, URL, **API token**, TLS, mTLS; `OPENCTI_<N>_*` in `.env` until the first change here). Use the token of a dedicated read-only OpenCTI user. Each instance answers IP, domain, URL, hash, threat actor and CVE; new ones start at risk 0 / knowledge 9.
- **Sources without a key** — Tor Exit Nodes, MITRE ATT&CK, RIPEstat, TweetFeed, CIRCL hashlookup, RDAP, Tranco, OpenPhish, SSLBL, CISA KEV and EPSS need no credentials (Spamhaus, Malpedia and NVD work without their optional keys) and are always active; they are listed so they can be tested too.
- **Test** — every row has one (disabled until a required key is set). It runs one real lookup of a harmless indicator (8.8.8.8, example.com, the EICAR hash, CVE-2021-44228…) against each source the row powers — all three for the abuse.ch key — with a progress bar and elapsed time while it runs. The result shows under the row, per source: the **test artifact** sent and its type, the response time, the outcome — *OK* (data returned), *OK · no record* (answered and accepted the key, nothing known about the artifact) or *Error* with the reason — and the source's raw JSON response (**Show response**, truncated above 60 000 characters). **Hide result** folds it to a one-line summary (**Show result** brings it back) and ✕ dismisses it. Rows can be tested at the same time. It uses one request of the source's quota — mind GreyNoise Community's 50 per week and CrowdSec's small monthly quota. The abuse.ch key row now also tests YARAify.

The home page lists only configured sources, so this page is where unconfigured ones are found. Changes apply to the next lookup, no restart. The list only shows the last four characters of each key. The eye on *Current key* fetches the full key on demand: admins only, from a signed-in browser session (never with an API token), sent with `Cache-Control: no-store` and logged by the backend (`Admin <user> revealed the <VAR> key`). They are stored in `backend/data/connectors.json` with permissions 0600, **in clear** (like `backend/.env`): protect the data volume and its backups accordingly.

---

## 1. The two scores in one minute

Every source that is queried ends up in one of five states:

| State | Meaning | Example |
|---|---|---|
| **Risk signal** (`hit`) | Returned a maliciousness signal | VirusTotal detections, a MISP attribute, a TweetFeed report |
| **Evaluated clean** (`clean`) | Explicitly evaluated the indicator as benign | VirusTotal file scan with 0/70 detections, GreyNoise RIOT, AbuseIPDB whitelist |
| **Context only** (`context`) | Has data, but no risk verdict | Shodan open ports, IPinfo geolocation |
| **No record** (`no_data`) | Answered, but doesn't know the indicator ("not found" included) | OTX with 0 pulses, TweetFeed `found: false` |
| **No answer** (`excluded`) | The lookup failed, or is still loading | Invalid key, rate limit, timeout |

Sources **without an API key**, **disabled** by the analyst, or that **don't support** the indicator type are not part of the lookup at all and never appear in either score.

### Knowledge Score (0–10) — *how much of our coverage has information*
Every configured, enabled source that supports the indicator type counts in the total — except those that failed for a temporary reason (see below). Each one adds its knowledge weight × its **depth of record** (`None` = 0, `Basic` = 0.5, `Rich` = 1). Sources with *No record* add 0.

```
coverage  = Σ(knowledge_weight × depth) / Σ(knowledge_weight of every counted source for that type)
knowledge = round( 10 × min(1, coverage ÷ knowledge_full_at) )      knowledge_full_at = 70 % by default
```

Consequences:
- Knowledge **only grows** as sources contribute — a source can never lower it by not knowing the indicator.
- It **saturates**: once `knowledge_full_at` % of the counted weight has a record, Knowledge is 10 — an indicator doesn't need *every* source to know it (see 2.5). With 100 % there is no saturation and 10 means every source has a rich record.
- A source that fails for a **temporary** reason — rate limit, timeout, network error, service unavailable / HTTP error, or the app couldn't reach the backend — is **left out of the total**: an API hiccup says nothing about the indicator. The breakdown shows it as *temporary error — not counted*.
- A **persistent** failure (invalid API key, forbidden) and a source **still loading** count in the total with depth 0, so knowledge only grows while results stream in.
- Knowledge only shows once at least one source has answered.

### Risk Score (0–10) — *how risky, according to sources that issued a verdict*
Only sources in **Risk signal** or **Evaluated clean** take part. *No record* and *Context only* stay out: not knowing an indicator is not the same as confirming it's benign.

```
risk = round( Σ(risk_weight × subscore) / Σ(risk_weight) )
```

If no source issued a verdict — or nothing at all is known about the indicator — the Risk Score shows **No data**, never `0`.

---

## 2. What you can change

The page has four blocks: an explanation box (read-only), **Quadrant thresholds**, **Knowledge saturation**, and the **per-source weights** table. A bar at the bottom holds **Save**, **Discard changes** and **Reset to defaults**.

### 2.1 Risk weight (per source)

*Column **Risk**. Range 0–10 (slider or number; the page won't accept values outside the range).*

How much that source's 0–10 risk subscore counts in the Risk Score, **relative to the other sources that issued a verdict on the same lookup**. Only the ratio between weights matters: setting every weight to 10 or every weight to 1 gives the same result.

| If you… | Effect |
|---|---|
| Raise it | The source's verdict pulls the Risk Score harder toward its own subscore — up if it reports a threat, **down if it reports clean or a weak signal**. |
| Lower it | Its verdict matters less; the other sources dominate. |
| Set it to `0` | The source is still queried and shown, but never affects the Risk Score. |

**Watch out for dominant weights.** A very high weight also amplifies *low* subscores. Example with real data for an IP reported as attacker infrastructure:

| Source | Risk weight | Subscore |
|---|:-:|:-:|
| Recorded Future | **10** | 1.0 |
| AbuseIPDB | 7 | 2.1 |
| AlienVault OTX | 6 | 4.0 |
| TweetFeed | 4 | 7.0 |

`risk = round((10×1.0 + 7×2.1 + 6×4.0 + 4×7.0) / 27) = round(2.84) = 3`. Setting Recorded Future's risk weight to **0** gives `round(66.7 / 17) = round(3.92) = 4`. The strong TweetFeed signal is diluted less.

**Risk weight has no effect on purely contextual sources** — Shodan, IPinfo, RIPEstat and MITRE ATT&CK never return a risk subscore, so raising their risk weight changes nothing. Their value lies in the Knowledge Score.

### 2.2 Knowledge weight (per source)

*Column **Knowledge**. Range 0–10 (slider or number; the page won't accept values outside the range).*

The share of the Knowledge Score that source can contribute: its weight divided by the total knowledge weight of all configured, enabled sources for the indicator type.

| If you… | Effect |
|---|---|
| Raise it | That source knowing the indicator adds more knowledge. It also enlarges the total, so every *other* source's share shrinks a little — and if this source has no record or fails, the indicator ends up with lower knowledge than before. |
| Lower it | Its answer matters less. Recommended for sources that answer for almost anything (IPinfo, RIPEstat) or only say yes/no (Tor exit list, Safe Browsing), so they can't inflate knowledge on their own. |
| Set it to `0` | The source never affects the Knowledge Score (it isn't part of the total either). |

### 2.3 Per-type knowledge overrides (per source)

*Button **Per type** on each row.*

Lets a source have a different knowledge weight for a specific indicator type (IP, Domain, URL, Hash, ASN, Actor, CVE). Only the types the source supports are shown.

- **Blank** → the general Knowledge value is used for that type.
- **A number** (0–10) → that number replaces the general value for that type only.

The built-in example is **RIPEstat**: knowledge weight 1 for IPs (it answers for any routed IP, so it says little), but **6 for ASNs**, where it is one of the very few sources available. Overrides only apply to the Knowledge Score — the risk weight is always the same for every type.

### 2.4 Quadrant thresholds

*Block **Quadrant thresholds (0–10)**.*

| Field | Default | Meaning |
|---|:-:|---|
| **Knowledge ≥** | 4 | From this Knowledge Score up, the indicator counts as **known**. |
| **Risk ≥** | 5 | From this Risk Score up, the indicator counts as **high risk**. It is also the level a *single* source's subscore must reach to count as a "strong signal" (see Known · Benign below). |

Thresholds are compared against the **rounded** scores, inclusive (`≥`).

How they map to the quadrant label:

| | Risk < threshold | Risk ≥ threshold |
|---|---|---|
| **Knowledge ≥ threshold** | Known · Benign / Known · Low-level signals / Known · No risk verdict | Malicious · Confirmed |
| **Knowledge < threshold** | Unknown | Isolated signal · Verify |

In the "known, low risk" cell the label depends on *why* the risk is low:

- **Known · Benign** — at least one source **explicitly evaluated it as clean**, *and* no single source returned a subscore ≥ the risk threshold.
- **Known · Low-level signals** — the average is below the threshold but it's made of risk signals, or a strong signal was diluted by others. Not a benign confirmation.
- **Known · No risk verdict** — sources have context on it, but none issued a risk verdict.

| If you… | Effect |
|---|---|
| Raise **Knowledge ≥** | Fewer indicators count as "known": more *Unknown* and *Isolated signal* labels, fewer *Confirmed*/*Benign*. Use it if you want corroboration from more sources before trusting a verdict. |
| Lower **Knowledge ≥** | Thinner evidence is enough to call something known. |
| Raise **Risk ≥** | Fewer indicators reach *Malicious · Confirmed* / *Isolated signal*. Individual strong signals also need to be stronger to block a *Known · Benign* label. |
| Lower **Risk ≥** | More indicators are flagged as high risk (more alerts, more false positives). |

Example: an indicator scoring Knowledge 4 is *known* with the default threshold (4); raising the threshold to 5 turns it into *Unknown*. Because a failing source lowers knowledge, a lookup during a provider outage can also drop below the threshold.

The thresholds only change the **label** — the two numbers are never affected by them.

---

### 2.5 Knowledge saturation

*Block **Knowledge saturation**. Range 10–100 %, default 70 %.*

The share of the counted knowledge weight (weighted by depth) at which the Knowledge Score reaches 10. Without it, a well-documented indicator that three broad sources simply don't have (e.g. AbuseIPDB, URLhaus, Shodan for a C2 IP) would stay around 5 even when the strongest sources know it in depth.

| If you… | Effect |
|---|---|
| Raise it | Harder to reach high knowledge: more of your sources must know the indicator. **100 %** = no saturation (the original linear formula). |
| Lower it | Fewer sources are enough to call something well known. Very low values make *Isolated signal* rarer. |

Example (real lookup): 29.5 of 54 counted weight → coverage 0.546 → `round(10 × min(1, 0.546 ÷ 0.70)) = 8` (it was 5 before saturation and with the rate-limited VirusTotal still counted).

Archived history entries keep the value in force when they were run; entries saved before this setting existed replay with 100 %.

## 3. Buttons

| Button | What it does |
|---|---|
| **Save** | Validates and stores every weight and both thresholds. Enabled only when there are unsaved changes. Every weight and threshold is limited to 0–10 (Knowledge saturation to 10–100 %): the inputs clamp to that range, and the backend rejects anything outside it with a message, saving nothing. |
| **Discard changes** | Throws away unsaved edits and shows the stored values again. |
| **Reset to defaults** | After a confirmation, deletes all admin changes and goes back to the built-in values (table below). Cannot be undone. |

---

## 4. When changes take effect

- **New lookups** use the new values. A results page that is already open keeps the values it loaded — reload it (or run the search again) to see the effect.
- **History is not rewritten.** Archived entries keep the scores, quadrant and weights in force when they were run. Entries saved before the two-score model only have a Risk Score; their Knowledge shows as `—`.
- **Ordering.** The home page source list and the results page sort sources by risk weight, then knowledge weight, so changing weights also changes the order.
- To see how a change plays out on a concrete indicator, open its results and use **View matrix** (step-by-step path from (0, 0) through each source) or **How is this calculated?** (per-source breakdown and formulas).
- The `R` / `K` chips on the home page and on every result card always show the current weights. On result cards the `K` chip also shows that source's depth for that lookup (`None` / `Basic` / `Rich`).

---

## 5. Where the values live

- **0–10 scale.** All weights use the 0–10 range. A `weights.json` saved by an older version with values above 10 (or a `MISP_<N>_*WEIGHT` above 10 in `.env`) is clamped to 10 when loaded, so review those rows and **Save** once.
- Saved values are stored in **`backend/data/weights.json`** — the same Docker volume as the query history — so they survive restarts, rebuilds and updates.
- Saving stores the **full set** of values shown on the page. After the first save, a future release that changes a *default* for an existing source won't override your saved value; use **Reset to defaults** to pick up new defaults. Sources added in a future release get their default weights automatically.
- **MISP and OpenCTI instances** start at risk 0 / knowledge 9 when added on the Connectors page; instances imported from `backend/.env` start at `MISP_<N>_WEIGHT` / `MISP_<N>_KNOWLEDGE_WEIGHT`. Once saved from Admin, the Admin value wins until you **Reset to defaults**.

---

## 6. Reference: defaults and scoring rules per source

### Default weights

| Source | Risk | Knowledge | Notes |
|---|:-:|:-:|---|
| Recorded Future | 10 | 9 | |
| MITRE ATT&CK | 0 | 9 | context only |
| MISP (each instance) | 0 (or `.env`) | 9 (or `.env`) | |
| OpenCTI (each instance) | 0 (or `.env`) | 9 (or `.env`) | |
| VirusTotal | 8 | 8 | |
| MalwareBazaar | 8 | 7 | |
| AlienVault OTX | 6 | 7 | |
| AbuseIPDB | 7 | 6 | |
| ThreatFox | 7 | 6 | |
| URLhaus | 7 | 6 | |
| ANY.RUN | 0 | 6 | |
| urlscan.io | 5 | 5 | |
| Shodan | 0 | 5 | context only |
| Hybrid Analysis | 0 | 5 | |
| GreyNoise | 0 | 5 | |
| PhishTank | 7 | 4 | |
| TweetFeed | 4 | 4 | |
| Safe Browsing | 0 | 3 | |
| Tor Exit List | 5 | 2 | |
| IPinfo | 0 | 1 | context only |
| RIPEstat | 0 | 1 (ASN: 6) | context only |
| CrowdSec CTI | 7 | 6 | |
| Malpedia | 0 | 7 | context only |
| CIRCL hashlookup | 4 | 5 | mostly clean verdicts |
| RDAP | 4 | 3 | young domains only |
| Tranco | 2 | 3 | clean verdicts only |
| Spamhaus | 8 | 5 (ASN: 6) | |
| OpenPhish | 7 | 3 | |
| YARAify | 5 | 4 | |
| SSLBL | 8 | 1 | SHA-1 certificate hashes only |
| CIRCL Passive DNS | 0 | 4 | context only |
| NVD | 6 | 9 | CVE only |
| EPSS | 8 | 6 | CVE only |
| CISA KEV | 10 | 3 | CVE only; listed CVEs only |

ANY.RUN, Hybrid Analysis, GreyNoise and Safe Browsing ship with risk weight 0: they are scored, but don't move the Risk Score until you give them a weight.

For **CVEs** the Risk Score means *exploitation risk*: NVD brings severity (CVSS), EPSS the probability of exploitation and CISA KEV confirmed exploitation, which is why KEV has the top risk weight and a low knowledge weight (most CVEs are not in it). The quadrants keep their logic but get vulnerability wording (*High exploitation risk*, *Known · Moderate risk*…).

CIRCL hashlookup, Tranco, CrowdSec and EPSS are the sources that most often issue an explicit **clean** verdict, which the *Known benign* quadrant needs. A clean verdict only counts with a risk weight above 0, and it also pulls the Risk Score down when other sources flag the indicator, which is why Tranco (popular domains can host abuse) and hashlookup (dual-use tools ship in distributions) have low risk weights.

### Risk subscore (0–10) per source

"No verdict" means the source stays out of the Risk Score for that lookup.

| Source | Rule |
|---|---|
| VirusTotal | malicious + suspicious detections: 0 → clean (0), 1–2 → 3, 3–5 → 6, >5 → 10. For **IPs and domains**, 0 detections on a profile with no community votes or tags → no verdict. |
| AbuseIPDB | abuse confidence ÷ 10. 0 confidence with 0 reports → no verdict; whitelisted → clean. |
| AlienVault OTX | pulses: 0 → no verdict, 1–2 → 4, 3–5 → 7, >5 → 10. **CVE**: seen in the wild → 9, public exploit → 7, pulses only → no verdict (context). |
| ThreatFox | no match → no verdict; match → 7 + (confidence ÷ 100 × 3) |
| URLhaus | no match → no verdict; URL online → 9, offline → 6 |
| MalwareBazaar | sample on file → 10, otherwise no verdict |
| Recorded Future | risk score ÷ 9.9. Score 0 with no risk rules triggered → no verdict. |
| urlscan.io | prior scans: 0 → no verdict, 1–2 → 3, 3–5 → 5, >5 → 6 |
| PhishTank | not in DB → no verdict; marked invalid → clean; unverified → 5; verified → 10 |
| ANY.RUN | no record → no verdict; threat level 0 → clean; 1 (suspicious) → 5; 2 (malicious) → 9 |
| GreyNoise | not observed → no verdict; malicious → 9; benign or RIOT → clean; scanning but unclassified → 4 |
| Hybrid Analysis | malicious → 9; suspicious → 5; whitelisted / no specific threat → clean; nothing or only "no verdict" → no verdict |
| Safe Browsing | on a threat list → 9; not listed → clean (a genuine real-time check) |
| Tor Exit List | exit node → 7; otherwise no verdict |
| MISP | matching attribute flagged `to_ids` (IDS) → 9; matches with `to_ids` off are context only (count for Knowledge, no risk verdict); no match → no verdict |
| OpenCTI | an **active** indicator (not revoked, still valid at lookup time) → its score ÷ 10 (7 if unscored; score 0 → no verdict); no active indicator → context. CVE: in CISA KEV → 9, related to an actor / malware / campaign → 8. Threat actor → context only. Never clean. |
| TweetFeed | not reported → no verdict; 1 reporter → 5; 2 → 6; ≥3, or a malware family / campaign → 7 (capped: reports are unvetted) |
| CrowdSec CTI | not reported or *unknown* → no verdict; known false positive, *safe* or *benign* → clean; *known* → 4; *suspicious* → 6; *malicious* → 9 |
| CIRCL hashlookup | known file → clean; also flagged `KnownMalicious` → no verdict; not found → no verdict |
| RDAP | domain registered < 7 days ago → 7; < 30 days → 5; older, unregistered or no date → no verdict |
| Tranco | the registered domain itself in the top 100 000 → clean; lower rank, a subdomain, or not listed → no verdict |
| Spamhaus | by return code: DROP, ASN-DROP, DBL phishing / malware / C&C → 9; SBL → 8; XBL, DBL spam → 7; CSS → 6; DBL abused legitimate → 5–6; PBL only or not listed → no verdict |
| OpenPhish | URL listed → 9; domain / IP hosting listed phishing → 7; URL on a host serving other listed phishing → 6; not listed → no verdict |
| YARAify | ClamAV signature → 7; YARA rules only, or not found → no verdict |
| SSLBL | certificate listed → 9; otherwise no verdict |
| NVD | CVSS base score as is (newest version: 4.0 → 3.1 → 3.0 → 2.0, NVD's own assessment first); rejected, not found or not scored yet → no verdict |
| CISA KEV | listed (exploited in the wild) → 9; also used in ransomware campaigns → 10; not listed → no verdict |
| EPSS | 30-day exploitation probability: ≥ 50 % → 10, ≥ 20 % → 8, ≥ 5 % → 6, ≥ 1 % → 3, < 1 % → clean; no score → no verdict |
| Shodan, IPinfo, RIPEstat, MITRE ATT&CK, Malpedia, CIRCL Passive DNS | never return a risk subscore |

### Depth of record per source (Knowledge Score)

| Source | None (0) | Basic (0.5) | Rich (1) |
|---|---|---|---|
| Recorded Future | not found | record without risk rules | ≥1 risk rule |
| MISP | 0 attributes | 1–2 attributes | ≥3 attributes or ≥2 events |
| OpenCTI | no match | entity with no indicators, relationships or reports | indicators, relationships or reports |
| MITRE ATT&CK | not found | profile without techniques | techniques or software |
| VirusTotal | not found | profile with no detections, votes or tags | detections, votes or tags |
| AlienVault OTX | 0 pulses | 1–2 pulses | ≥3 pulses (CVE: also seen in the wild or a public exploit) |
| MalwareBazaar | no sample | — | sample on file |
| AbuseIPDB | 0 reports | 1–9 reports | ≥10 reports or whitelisted |
| ThreatFox | no match | — | ≥1 IOC |
| URLhaus | no match | 1 related URL | ≥2 URLs, or the URL with payloads |
| ANY.RUN | no record | threat level 0 | threat level ≥1 |
| Shodan | not found / ASN with 0 hosts | 1–2 ports, no vulns or tags | ≥3 ports, vulns or tags; ASN with hosts |
| Hybrid Analysis | no results | only "no verdict" | any verdict |
| urlscan.io | 0 scans | 1–2 scans | ≥3 scans |
| GreyNoise | not observed | scanning, unclassified | classified or RIOT |
| PhishTank | not in DB | unverified | verified |
| TweetFeed | not reported | 1 reporter, 1 tweet | ≥2 reporters, ≥2 tweets, or part of a campaign |
| Safe Browsing | not listed | — | listed |
| Tor Exit List | not an exit node | — | exit node |
| IPinfo | bogon | any answer | — |
| RIPEstat | no announced route | announced prefix (IP) | ASN holder found (ASN) |
| CrowdSec CTI | not reported | *known* / *unknown*, no behaviours | behaviours, false positive, or a firm reputation |
| CIRCL hashlookup | not found | single source (trust 50) | trust > 50 or parent packages |
| RDAP | not registered | registration record | — |
| Tranco | not listed or a subdomain | rank 100 001 – 1M | top 100 000 |
| Malpedia | no actor matched | profile only | description or attributed families |
| Spamhaus | not listed | PBL only | any scored listing |
| OpenPhish | not listed | other URLs on the same host | listed itself (URL) / host serving phishing |
| YARAify | never submitted | submitted, no matches | YARA or ClamAV matches |
| SSLBL | not listed / not a SHA-1 | — | listed |
| CIRCL Passive DNS | no records | 1–4 records | ≥5 records |
| NVD | not found | rejected, or no CVSS yet | scored record |
| CISA KEV | not listed | — | listed |
| EPSS | no score | — | scored |

These rules are fixed in code (`frontend/src/verdictEngine.ts`); the Admin page only changes how much each source's result counts.
