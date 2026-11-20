# User guide — reading a lookup

How IntelChecker turns the answers of every CTI source into a verdict, and how to read the results page. The same content is available in the app (header → **Docs**, in English and Spanish) together with this deployment's live weights. Every Admin setting is explained in [admin.md](admin.md).

---

## 1. Running a lookup

Sign in with the account your admin gave you (the first time you'll be asked to choose your own password). Running lookups needs the **Analyst** or **Admin** role; **Readers** can only browse History. Roles are described in [admin.md § 0](admin.md#0-users-and-roles).

Type an indicator on the home page, pick its type (IP, Domain, URL, File Hash, ASN, Threat Actor) and press **Analyze**. Every source that supports the type is queried **in parallel**, and each card appears as soon as its own source answers.

- The source list under the search box shows which sources are connected. Its switch turns a source off for that browser; disabled sources aren't queried and don't count in any score.
- Each source shows its **R** (risk) and **K** (knowledge) weight. Sources are sorted by risk weight, then knowledge weight.
- Sources without an API key are listed as **Not configured** and are left out of the lookup. On the results page they appear as a greyed-out **Off · not configured** card, never as an error.
- Lookups are always live — nothing is cached.

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

Default thresholds: knowledge ≥ 4, risk ≥ 5 (both editable in Admin). The per-source subscore and depth rules are listed in [admin.md § 6](admin.md#6-reference-defaults-and-scoring-rules-per-source).

## 3. The results page

### Summary

- **Score panel** (right) — a card bordered and lit in the quadrant's colour, with the **quadrant label**, the **Risk** gauge (semicircle, green → red gradient, with a tick on the "high risk" threshold), the **Knowledge** bar (its vertical mark, labelled underneath, is the "known" threshold), how many sources answered, and the **View matrix** / **How is this calculated?** buttons.
- **Flagged by** — reads "**N** sources flag it as malicious · M responded · K not configured": N sources returned a risk signal (each with its subscore), M answered, and K support the type but have no API key (shown only when K > 0). Sources that gave a clean verdict are listed underneath. Sources with risk weight 0 are shown dashed (they flagged it but don't count in Risk).
- **Malware families** — from structured fields only (ThreatFox, MalwareBazaar, OTX, MISP galaxies, VirusTotal, Hybrid Analysis, ANY.RUN, TweetFeed), with aliases merged (Qbot / QakBot / Pinkslipbot) using a built-in table plus MITRE ATT&CK software aliases. Families that only come from bulk OTX pulses (weekly roundups, feeds with ≥ 100 indicators) are ignored. Click a family to see exactly where it comes from: source, field, raw value and pulse / MISP event.
- **Threat actor relations** — one row per actor with every source that relates the indicator to it (OTX pulse adversaries, MISP threat-actor galaxies, actor names found in any source's tags, matched against MITRE ATT&CK). Recorded Future "Linked to APT" rules appear as unnamed relations. If sources answered and none relates it to an actor, the block says so. Campaigns (TweetFeed) are listed underneath.
- **Activity window** — earliest first-seen and latest last-seen across all sources.
- **GeoIP · ASN · ISP · Tor · Ports** — network context with how many sources agree on each value.

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
| `Off · not configured` / `Disabled` (grey, power icon) | Not part of the lookup: no API key in `backend/.env`, or switched off on the home page. Not queried, not counted in either score. History entries show it the same way. |

## 4. History and search frequency

Every completed lookup is stored in `backend/data/history.db` with the user who ran it and a **frozen snapshot**: both scores, the quadrant, every source's contribution and raw response. **History** (header) lists them, optionally filtered by indicator; opening one shows the result exactly as it was — later weight changes never rewrite history. Entries from before the two-score model only have a Risk Score.

The **Search Frequency** card counts how many *other* times the same indicator was looked up (the current lookup never counts itself). Its colour is whichever window reads most severe; any hit within 72 h is at least yellow:

| Level | 24 h | 72 h | 30 d |
|---|:-:|:-:|:-:|
| ⬜ Grey — no other activity | 0 | 0 | 0 |
| 🟩 Green — stale only | — | — | 1–3 |
| 🟨 Yellow | 1 | 1–4 | 4–8 |
| 🟧 Orange | 2–4 | 5–7 | 9–15 |
| 🟥 Red | 5+ | 8+ | 16+ |

**View all** opens History filtered to that indicator.
