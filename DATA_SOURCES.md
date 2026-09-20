# Real intelligence and publication

## Included reference collection

Admin → Sources → Load sourced starter collection stages five historical reference records: APT28, APT29, the SolarWinds compromise campaign WannaCry and a historical WannaCry C2 indicator. Summaries are short original paraphrases checked against their MITRE pages on 2026-09-19. The campaign–APT29 relationship is explicit in the source. These are real reference records, not invented personal incidents or a live news feed.

- https://attack.mitre.org/groups/G0007/
- https://attack.mitre.org/groups/G0016/
- https://attack.mitre.org/campaigns/C0024/
- https://attack.mitre.org/software/S0366/

The historical IOC is `gx7ekbenv2riucmf.onion`, listed as a WannaCry C2 address by Secureworks CTU: https://www.sophos.com/en-us/research/wcry-ransomware-analysis . It is stored as a historical malicious observation with no invented confidence score or observation date. After review and publication, use that text in the lookup box; do not navigate to it.

## Live imports

Admin → Sources offers CISA KEV and MITRE ATT&CK synchronization. Records enter Incoming; no automatic public publication. CISA adds missing CVEs without replacing your existing vulnerability descriptions or severity. MITRE maps groups to actors, campaigns to campaigns, and malware/techniques to threats. Relationships are imported only when both supported endpoints exist. Legacy directory and incident tables are not filled with invented data.

Official references:
- CISA catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- ATT&CK data: https://attack.mitre.org/resources/attack-data-and-tools/
- ATT&CK source repository: https://github.com/mitre-attack/attack-stix-data
- ATT&CK terms: https://attack.mitre.org/resources/legal-and-branding/

Command-line imports, including offline files:

```bash
.venv/bin/python feeds.py all
.venv/bin/python feeds.py cisa --file /path/to/known_exploited_vulnerabilities.json
.venv/bin/python feeds.py mitre --file /path/to/enterprise-attack.json
.venv/bin/python feeds.py ioc-csv --file /path/to/indicators.csv
```

The CSV columns are:
`type,value,verdict,source_name,source_url,description,confidence,first_seen,last_seen`

Required: the first five. Types: ip, domain, url, md5, sha1, sha256. Verdicts: malicious, suspicious, benign, unknown. Confidence is optional 0–100; omit if the source does not supply one. Dates should be ISO 8601 timestamps. Source URLs must be HTTPS references. Do not use a malware download URL as an evidence link.

URLhaus requires an Auth-Key and has usage and redistribution terms: https://urlhaus.abuse.ch/api/ . The app does not download malware, bypass source authentication, or include a URLhaus API key. Obtain permitted data, convert it to the documented CSV, then import locally. A collected payload is not automatically malicious; preserve the provider's actual verdict. No public query is sent to an external reputation service.

## Review and publication

1. Analyst opens Desk → Incoming.
2. Check the original source, public summary and indicator verdict. Save review notes.
3. For public submissions, replace the unverified source name/reference while saving Review first. A later action can mark the item Ready.
4. Admin opens Ready and publishes approved items.
5. The public catalogue and exact IOC lookup now include those records.
6. Admin may withdraw a published item. Subsequent feed content changes return an item to Incoming; MITRE revoked/deprecated objects are withdrawn.

Published summaries are not live views of editable internal tables. Internal table edits do not silently publish private information. Public detail responses omit raw payloads, submission notes, reviewer notes and account IDs.

## Scheduled synchronization

No operating-system scheduler is installed automatically. A local scheduler may run `.venv/bin/python feeds.py all` from the project directory once daily. Keep the machine online and running PostgreSQL. Review the import log; new records still require editorial approval. Configure rate and licensing limits before adding more feeds.

## Coverage limits

This is a historical intelligence database, not a live antivirus or URL scanner. File hashes identify exact bytes, not similar files. IPs can be reassigned and domains can be cleaned up. URL host matches are shown separately from exact URL matches. An unknown result never means safe.

Real public sources populate the relevant intelligence/source/relationship tables. Accounts, audits, investigations and private notes are populated by actual platform activity. The schema now has 36 application tables (26 original + 5 account/research tables + 5 public-intelligence tables); it is not restricted to the earlier 31-table count. Your actual database may also contain unrelated tables.
