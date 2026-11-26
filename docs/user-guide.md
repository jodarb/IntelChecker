# User guide — reading a lookup

How IntelChecker turns the answers of every CTI source into a verdict, and how to read the results page. The same content is available in the app (header → **Docs**, in English and Spanish) together with this deployment's live weights. Every Admin setting is explained in [admin.md](admin.md).

---

## 1. Running a lookup

Sign in with the account your admin gave you (the first time you'll be asked to choose your own password). Running lookups needs the **Analyst** or **Admin** role; **Readers** can only browse History. Roles are described in [admin.md § 0](admin.md#0-users-and-roles).

Type an indicator on the home page, pick its type (IP, Domain, URL, File Hash, ASN, Vulnerability (CVE)) and press **Analyze**. Three tabs under the header switch between the search tools: **Artifacts** (indicators, this section), **Actors** (threat actors by name or alias, e.g. `APT28`: the same results page, only the threat-actor sources; pressing **Search** first lists the matching actors — even misspelled, `Gentleman` finds *The Gentlemen* — with aliases, sources and whether it is a ransomware group, and the one you pick is looked up by the name most sources know it by; RF-only individuals and forum handles are folded apart, and *Search as typed* skips the list) and **Companies** (below). Every source that supports the type is queried **in parallel**, and each card appears as soon as its own source answers.

- The source list under the search box shows only the configured sources (admins also see how many are missing, with a link to **Connectors**). Its switch turns a source off for that browser; disabled sources aren't queried and don't count in any score.
- Each source shows its **R** (risk) and **K** (knowledge) weight. Sources are sorted by risk weight, then knowledge weight.
- Sources without an API key are left out of the lookup and **not shown on the results page** at all (the Summary says how many there are).
- **Card order on the results page** (and in History entries): first the sources with a result, highest risk subscore first — clean (0) before context-only — and, on ties, the larger Knowledge contribution (knowledge weight × depth). Then the sources still loading, and at the end those without a result: no record, errors, and sources you switched off. Cards move up as their answers arrive.
- Lookups are always live — nothing is cached.
- **Companies** (the **Companies** tab, `/companies`): its own sources, and a **company report** instead of the artifact results — the profile (sector, headquarters, countries, legal entity, parent, employees, website), four exposure tiles (dark web · ransomware, infostealers, data breaches, incidents in the news), an incident timeline and, at the end, the per-source cards. History entries of companies open in the same report. For now the company report, its source cards and the History list show no risk/knowledge scores or weights for companies (the verdict is still computed and saved). A company name is ambiguous ("Iberia" is an airline, a piano suite and a peninsula), so pressing **Analyze** first lists the matching **Wikidata** organisations with country, domain and Wikidata id. Pick one and it is searched as `Name (domain, Q-id[, LEI])`, so every source — and the history — refers to that exact entity. *Search as typed* uses only what you wrote. You can also type that format yourself, e.g. `Iberia (iberia.com)`, or just a domain. Hudson Rock and Have I Been Pwned search by domain: without one they say so and are left out of Knowledge.

## 2. The two scores

Every lookup produces **two independent scores** and a quadrant reading of both.

### Source outcomes

Before scoring, each source's answer is classified:

| Outcome | Meaning | Knowledge | Risk |
|---|---|:-:|:-:|
| **Risk signal** | Returned a maliciousness signal | ✓ | ✓ |
| **Evaluated clean** | Explicitly evaluated it as benign (VT file scan 0/70, GreyNoise RIOT, AbuseIPDB whitelist) | ✓ | ✓ |
| **Context only** | Has data but no verdict (Shodan ports, IPinfo geolocation) | ✓ | — |
| **No record** | Answered but doesn't know it ("not found") | adds 0 | — |
| **No answer** | The lookup failed or is still loading | adds 0 | — |

**"Not found" is never "clean".** A source that has never seen an indicator hasn't vouched for it.

### Knowledge Score (0–10) — how much is known

It measures how much of the configured coverage has information on the indicator, good or bad. Each source rates its **depth of record**: `None` (0), `Basic` (0.5 — a generic profile, a single report) or `Rich` (1 — several reports, samples, verdicts…).

```
coverage  = Σ(knowledge_weight × depth) / Σ(knowledge_weight of every counted source for the type)
knowledge = round(10 × min(1, coverage ÷ knowledge_full_at))      # knowledge_full_at = 70 % by default
```

- It **only grows** as sources answer; a source with no record adds nothing.
- It **saturates**: once `knowledge_full_at` % of the counted weight has a record, Knowledge is already 10 — an indicator doesn't need *every* source to know it.
- A source that fails for a **temporary** reason (rate limit, timeout, network, service unavailable) is left out of the total. A persistent failure (invalid key, forbidden) or a source still loading counts with depth 0.
- Sources that answer for almost anything (IPinfo, RIPEstat) or only say yes/no (Tor exit list, Safe Browsing) carry low knowledge weights, so they can't inflate the score.

### Risk Score (0–10) — how risky, per sources with a verdict

```
risk = round(Σ(risk_weight × subscore) / Σ(risk_weight))
```

Only sources with an actual verdict (*Risk signal* or *Evaluated clean*) take part. If none issued one, Risk shows **No data**, never a clean `0`. A heavy source pulls the average towards its own subscore in both directions.

### Quadrant

| | Risk < threshold | Risk ≥ threshold |
|---|---|---|
| **Knowledge ≥ threshold** | Known · Benign / Known · Low-level signals / Known · No risk verdict | Malicious · Confirmed |
| **Knowledge < threshold** | Unknown | Isolated signal · Verify |

In the "known, low risk" cell the label depends on *why* the risk is low:

- **Known · Benign** — at least one source explicitly evaluated it as clean, and no single source scored at or above the risk threshold.
- **Known · Low-level signals** — the average is low but made of risk signals (or a strong signal was diluted). Not a benign confirmation.
- **Known · No risk verdict** — sources have context, but none issued a verdict.

**Vulnerabilities (CVE)** use the same quadrants with wording about *exploitation risk*: *High exploitation risk*, *High risk · Little data*, *Known · Low risk*, *Known · Moderate risk* (e.g. a severe CVE that is unlikely to be exploited), *Known · Not scored* and *Unknown CVE*. Risk combines NVD's CVSS, the EPSS probability, CISA KEV and VulnCheck KEV (known exploitation) and OTX (seen in the wild, public exploits).

**Companies** use the same quadrants with wording about *exposure* — the company as a victim: *High exposure*, *Exposure · Little data*, *Known · No exposure found*, *Known · Low exposure*, *Known · No exposure data* and *Unknown company*. Risk combines ransomware leak-site claims (ransomware.live), infostealer infections of employees (Hudson Rock) and public breaches (Have I Been Pwned); Knowledge also counts how well Wikidata and GLEIF identify the company, recent incident headlines (GDELT) and the threats Recorded Future ties to it (actors, ransomware groups, malware, phishing infrastructure).

**Threat actors** have no Risk score and no quadrant (no source issues a risk verdict on an actor): their report shows **Activity** next to Knowledge — *Active* (seen in the last 90 days), *Recently active* (last year), *Dormant* (older) or *No activity data*, with the last operation (victims claimed on its leak site per ransomware.live, OpenCTI last seen), the last report (OTX pulses, OpenCTI reports, Recorded Future Threat Map changes) and the counts for the last 90 days. Profile edits (MITRE ATT&CK, Malpedia) don't count. History entries measure it from the day the lookup ran, and the History list shows only their Knowledge. Activity is not part of the verdict.

Default thresholds: knowledge ≥ 4, risk ≥ 5 (both editable in Admin). The per-source subscore and depth rules are listed in [admin.md § 6](admin.md#6-reference-defaults-and-scoring-rules-per-source).

## 3. The results page

### Summary

- **Score panel** (right) — a card bordered and lit in the quadrant's colour, with the **quadrant label**, the **Risk** gauge (semicircle, green → red gradient, with a tick on the "high risk" threshold), the **Knowledge** bar (its vertical mark, labelled underneath, is the "known" threshold), how many sources answered, and the **View matrix** / **How is this calculated?** buttons.
- **Flagged by** — reads "**N** sources flag it as malicious · M responded · K not configured": N sources returned a risk signal (each with its subscore), M answered, and K support the type but have no API key (shown only when K > 0). Sources that gave a clean verdict are listed underneath. Sources with risk weight 0 are shown dashed (they flagged it but don't count in Risk).
- **Malware families** — from structured fields only (ThreatFox, MalwareBazaar, OTX, MISP galaxies, OpenCTI related malware, VirusTotal, Hybrid Analysis, ANY.RUN, TweetFeed, Malpedia, SSLBL), with aliases merged (Qbot / QakBot / Pinkslipbot) using a built-in table plus MITRE ATT&CK software aliases. Families that only come from bulk OTX pulses (weekly roundups, feeds with ≥ 100 indicators) are ignored. Click a family to see exactly where it comes from: source, field, raw value and pulse / MISP event.
- **Threat actor relations** — one row per actor with every source that relates the indicator to it (OTX pulse adversaries, MISP threat-actor galaxies, OpenCTI related actors, actors and malware Recorded Future links to the indicator (only when its RF risk is ≥ 25: below that, links describe what uses the infrastructure), the Malpedia actor profile, actor names found in any source's tags, matched against MITRE ATT&CK). Recorded Future "Linked to APT" rules appear as unnamed relations. If sources answered and none relates it to an actor, the block says so. Campaigns (TweetFeed) are listed underneath.
- **Activity window** — earliest first-seen and latest last-seen across all sources.
- **GeoIP · ASN · ISP · Tor · Ports** — network context with how many sources agree on each value.
- **Company profile & exposure** — for company lookups: ransomware leak-site claims (count · groups · last), infostealers (infected employees / users), public breaches, incident headlines, sector, headquarters country, countries with subsidiaries, legal entity (LEI) and employees. The ransomware groups that claimed it show up as threat actor relations and the infostealer families as malware families.
- **Threat actor report** — threat actors get their own report instead of the Summary. A compact **card** on top: name, MITRE id, ransomware / RaaS and leak sites, the aliases that aren't just spellings of the name, a three-line description, key figures (victims claimed and in the last 90 days for ransomware groups — reports in the last 90 days otherwise —, TTPs, related artifacts, exploited CVEs, own tools), most targeted sectors and countries, the TTPs several sources confirm and its own arsenal; on the side its **Activity**, Knowledge and the sources that identified it. Below, the detail in **fixed tabs**, whatever sources are deployed (an empty one says which sources were asked): *Victims and incidents* (latest leak-site victims, campaigns / incidents / reports, linked organisations), *TTPs* (ATT&CK id, technique, sources), *Vulnerabilities*, *Artifacts* (filter by type, sorted by the risk score a source gives, each one a click from its lookup), *Arsenal* (attributed — a source says it uses them, they carry its name or several sources agree — apart from what a single source merely mentions alongside it) and *Leak sites* (its walls of shame, negotiation chats and file servers: online / down, type, page title, last check; the address is shown as text to copy, never opened); every value says which source it comes from, and the per-source cards follow below, as for artifacts. Before building it, the report checks **which actor each source identified** and groups them by shared names: a confirmed actor (a curated catalogue matched exactly, or two sources agree) gets the full card; a single-source or closest match gets a warning; a Recorded Future forum member gets a reduced *person* card ("a person or handle, not a threat group"); sources that matched different actors get a list of the others with a link to search each; and when no source identifies an actor there is no card, only *Did you mean…* suggestions and OTX's unverified free-text mentions. History entries open in the same report.
- **CVSS · Exploited (KEV) · EPSS** — for CVE lookups: the CVSS score and severity, whether it's a known exploited vulnerability (reported by CISA KEV, VulnCheck KEV and NVD) and the EPSS probability with its percentile. The NVD publication date is the CVE's *first seen*.

### Matrix view and breakdown

- **View matrix** plots Knowledge (X) × Risk (Y) and replays the verdict source by source from (0, 0), in the same order as the cards. Hover a step to highlight it.
- **How is this calculated?** shows every source's contribution (weight, depth, subscore) and the formulas filled in with the lookup's numbers.

### Per-source cards

Each card links to the indicator on the original tool and has a `RAW` button with the exact JSON it returned. Its badge keeps these situations apart:

| Badge | Meaning |
|---|---|
| Solid pill (green → red) | An actual 0–10 risk verdict. `0` is an explicit "evaluated and clean". |
| `No results` (soft, yellow) | The source has no record of the indicator. |
| `No score` (soft, yellow) | Real data, but nothing to score (Shodan host, IPinfo geolocation). |
| `Error` (soft, red) | The lookup failed; the card says why (invalid key, rate limit, timeout…). |
| `Disabled` (grey, power icon) | Switched off on the home page: not queried, not counted in either score. Shown at the end of the list. (Sources without an API key are not shown at all.) |

## 4. History and search frequency

Every completed lookup is stored in `backend/data/history.db` with the user who ran it (lookups made through the [API](api.md) are tagged **API**) and a **frozen snapshot**: both scores, the quadrant, every source's contribution and raw response. **History** (header) lists them, optionally filtered by indicator; opening one shows the result exactly as it was — later weight changes never rewrite history. Entries from before the two-score model only have a Risk Score.

The **Search Frequency** card counts how many *other* times the same indicator was looked up (the current lookup never counts itself). Its colour is whichever window reads most severe; any hit within 72 h is at least yellow:

| Level | 24 h | 72 h | 30 d |
|---|:-:|:-:|:-:|
| ⬜ Grey — no other activity | 0 | 0 | 0 |
| 🟩 Green — stale only | — | — | 1–3 |
| 🟨 Yellow | 1 | 1–4 | 4–8 |
| 🟧 Orange | 2–4 | 5–7 | 9–15 |
| 🟥 Red | 5+ | 8+ | 16+ |

**View all** opens History filtered to that indicator.
