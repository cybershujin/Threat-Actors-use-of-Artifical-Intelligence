# IOCs — source of truth for STIX indicators

One CSV per report. `tools/build_exports.py` reads every `iocs/*.csv` and emits, for each row, a
STIX 2.1 `indicator` object (plus an observable SCO and an `indicates` relationship to the matching
actor) into `stix/threat-actors-ai-stix2.1.json`. This runs automatically in CI on every push to
`main` that touches `iocs/**` (see `.github/workflows/build-exports.yml`).

**File naming:** `<YYYYMMDD>_<vendor>_<slug>.csv` (report publication date + source), e.g.
`20260910_anthropic_ai_misuse_september_2026.csv`. Use `TEMPLATE.csv` as the starting header.

## The one rule: never guess

Fill a cell **only** when the primary source states it. A blank cell is left blank — it is not a
zero, not "unknown", not a default. The builder emits a STIX property only when its cell is
non-empty, so blanks simply don't appear in the feed. Do **not** invent `first_seen`, `last_seen`,
`role`, `handling`, or `platform` to make a row look complete. Ingest only indicators the source
explicitly attributes to the actor.

## Columns

| Column | Required | Meaning | Maps to (STIX) |
| --- | --- | --- | --- |
| `id` | recommended | `indicator--<uuid>`. Copy the vendor's ID verbatim when they publish one; otherwise leave blank and the builder derives a stable UUIDv5 from the value. | `indicator.id` |
| `gtg` | recommended | Actor/case tracking code (e.g. `GTG-20006`). Used to link the indicator to its actor row; a code with no matching row is emitted **unlinked** (not an error). | → `indicates` relationship + `x_gtg` |
| `case_study` | optional | The report's case-study name. | `x_case_study` |
| `harm_area` | optional | e.g. `cyber_operations`, `influence_operations`, `surveillance`, `scams_fraud`. | `x_harm_area` |
| `type` | **required** | Observable type (vocab below). | drives `pattern` + SCO |
| `platform` | optional | e.g. `telegram`, `x`, `youtube`, `instagram` (for account types). | `x_platform` + `user-account.account_type` |
| `value` | **required** | The observable, **defanged** (`ad-g[.]org`, `104.194.151[.]184`, `https[:]//…`). The builder refangs it for the STIX pattern and keeps the defanged form in `indicator.name`. | `pattern` / SCO value |
| `role` | optional | Function of the indicator (IOA context): e.g. `c2`, `infrastructure`, `phishing`, `malware`, `malware_delivery`, `egress`, `exfiltration`, `staging`, `monetization`, `persona`, `persistence`. | `labels` + `x_ioc_role` |
| `description` | optional | Free-text note from the source. | `indicator.description` |
| `first_seen` | optional | ISO date the activity began (`YYYY-MM-DD`, `YYYY-MM`, or `YYYY`). | `valid_from` (else falls back to `report_date`) |
| `last_seen` | optional | ISO date activity last observed. | `valid_until` (only if after `valid_from`) |
| `handling` | optional | Recommended disposition **as stated by the source**: `detect-or-block` or `hunt`. | `labels` + `x_handling` |
| `reference_url` | recommended | Link to the report / IOC section. | `indicator.external_references` |
| `report_date` | recommended | Report publication date (`YYYY-MM-DD`). | `indicator.created` + `valid_from` fallback |

## `type` vocabulary → STIX pattern

| `type` | STIX pattern | SCO |
| --- | --- | --- |
| `domain`, `hostname` | `[domain-name:value = '…']` | domain-name |
| `ipv4` | `[ipv4-addr:value = '…']` | ipv4-addr |
| `ipv6` | `[ipv6-addr:value = '…']` | ipv6-addr |
| `url`, `onion` | `[url:value = '…']` | url |
| `email` | `[email-addr:value = '…']` | email-addr |
| `sha256` | `[file:hashes.'SHA-256' = '…']` | file |
| `filename`, `filepath` | `[file:name = '…']` | file |
| `android_package`, `app_id` | `[software:name = '…']` | software |
| `account` (URL value) | `[url:value = '…']` | url |
| `account`, `telegram_user_id` | `[user-account:account_type='<platform>' AND user-account:user_id='…']` | user-account |
| `telegram_bot_id`, `telegram_chat_id` | `[user-account:account_type='telegram' AND user-account:user_id='…']` (+ `x_telegram_id_kind`) | user-account |
| `scheduled_task` | `[process:name = '…']` | — |

A `type` not in this list still becomes an `indicator` (its raw type preserved in `x_ioc_type`); add
a new mapping to `ioc_pattern_and_sco()` in `tools/build_exports.py` when a new type recurs.

## Every indicator carries (only when the cell is present)

`x_ioc_type` (raw granular type, always kept so no detail is lost), `x_ioc_role`, `x_handling`,
`x_gtg`, `x_harm_area`, `x_case_study`, `x_platform`. `indicator_types` is always
`["malicious-activity"]` (definitional for a reported IOC). The build is deterministic and
idempotent — re-running it produces byte-identical output.
