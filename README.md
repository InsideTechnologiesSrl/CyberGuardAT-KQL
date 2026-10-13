# CyberGuardAT-KQL

A curated library of KQL (Kusto Query Language) hunting queries for **Microsoft Sentinel** and
**Microsoft Defender XDR advanced hunting**.

## What it does

Every query is a single YAML file, organised by technology (Entra ID, Defender for Endpoint,
Defender for Office 365, Exchange Online, Azure Activity, …) and mapped to MITRE ATT&CK tactics and
techniques. The format follows the hunting query schema used in the official
[Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository, so the queries can be copied
into Sentinel or Defender as they are.

An `index.json`, rebuilt and validated on every change, lets tools load the whole catalogue in a
single request.

## Why it exists

Good hunting queries are spread across blog posts, gists and forums, often untested and with no
context. This library collects queries that have been researched, tested and documented in real
environments, each one explaining what it detects and how to read the results.

## Community

The library is free for everyone to use, copy and adapt. Queries come from our own research and from
the wider security community: when a query is based on someone else's work, its author is credited
in the file.

To keep quality and consistency high, the repository is fully managed by Inside Technologies and
does not accept external pull requests or issues. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Where it is used

The same catalogue is available in the **CyberGuard Assessment Tool** and in the free
**Microsoft Sentinel Toolkit**, where queries can be browsed by technology or MITRE technique and run
against your own environment.

## Repository layout

```
queries/
  groups.json                 # technology groups: folder key, display name, colour
  entra-id/
    <query-name>.yaml
  defender-for-endpoint/
    <query-name>.yaml
  ...
index.json                    # generated: every query in one file
tools/build-index.mjs         # validation and index generation
```

## Query format

```yaml
id: 07280ca1-dd4c-5ceb-8341-db2c4b6a9bdb   # stable GUID, never changes
name: 'Brute Force — Sign-in failures per user (last 24h)'
description: |
  What the query detects and how to read the results.
group: entra-id                            # must match the folder name
tactics:                                   # MITRE ATT&CK tactics
  - InitialAccess
relevantTechniques:                        # MITRE ATT&CK techniques (e.g. T1110.003)
  - T1110
# mitreNotApplicable: 'reason'             # only for operational queries with no ATT&CK mapping
tags:
  - BruteForce
requiredDataConnectors: []                 # optional, Azure-Sentinel style
version: 1.0.0
added: 2025-01-01
updated: 2026-10-13                        # optional
author: Silvio Di Benedetto
credits: 'Original idea by …'              # optional, when based on someone else's work
query: |
  SigninLogs
  | where TimeGenerated > ago(24h)
  ...
```

## MITRE ATT&CK mapping

Every query is mapped to the techniques it helps detect or investigate, and to the tactics those
techniques belong to, using the current ATT&CK Enterprise release (tactic names as in ATT&CK v19,
e.g. `Stealth` and `DefenseImpairment`). Validation rejects unknown, revoked or deprecated techniques
and tactics not covered by the listed techniques. Purely operational queries carry a
`mitreNotApplicable` reason instead. The reference in `tools/attack-enterprise.json` is refreshed
from MITRE every month.

## Using the catalogue

The whole catalogue is published as a single file:

```
https://raw.githubusercontent.com/InsideTechnologiesSrl/CyberGuardAT-KQL/main/index.json
```

## License

[MIT](LICENSE) © Inside Technologies Srl
