# Risk Model

The path score is the sum of six explainable components, capped at 100.

## 1. Exposure

An externally exposed or external-zone source adds a fixed exposure contribution because internet reachability increases the potential attack surface.

## 2. Vulnerability

Each asset's highest modeled vulnerability score (0–10) contributes to the path. Intermediate nodes receive a lower weight than the destination so a vulnerable critical target remains important without making every transit node equally dominant.

## 3. Criticality

Asset criticality is modeled on a 1–10 scale. Higher-value assets contribute more to the score.

## 4. Service exposure

Sensitive services receive additional weight. Current examples include SSH, Telnet, RDP, MySQL, PostgreSQL, Redis, and SMB.

## 5. Segmentation

Moving from a lower-trust zone to a higher-trust zone increases risk. The modeled zones are `external`, `dmz`, `internal`, and `restricted`.

## 6. Path complexity

Longer attack chains receive a bounded complexity contribution. The cap prevents hop count from overwhelming stronger security signals such as vulnerabilities or exposure.

## Severity

- `critical`: 80+
- `high`: 60–79.9
- `medium`: 35–59.9
- `low`: below 35

## Design principle

The model is intentionally transparent. Every score can be decomposed into the six factors, and the UI exposes those values so an analyst can understand why a route ranked highly.
