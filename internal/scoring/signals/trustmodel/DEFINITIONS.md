# TrustModel Trust Index Signals — Definitions

Narrow, functional, and defensible definitions for the three signals this package
registers to fill the ANS `agent-trust-discovery` dimensions that are empty in v1
(`solvency`, `behavior`, `safety`; `dimensionWeight 0` in the default profile).

Design rules that make each definition defensible:

1. **Scoped** — every signal states what it does *not* measure, so the dimension
   cannot silently expand.
2. **Functional** — the score is computed from observable, auditable inputs, not
   opinion. No single-judge subjective scoring.
3. **Reproducible** — the score is recomputable from its evidence bundle, so a
   relying party or resolver can audit rather than trust the number.
4. **Evidenced** — every observation carries `provenance{aimId, evidenceUrl}`
   pointing at the record it was derived from.

All signals emit on the existing `port.Signal` contract and set
`Attestation = Unattested` (the score is asserted by the provider; the receipt,
not the signal, is the attestation).

---

## 1. `trustscore.solvency` — Operator Accountability

**Dimension:** `solvency`

**Definition.** The degree to which the agent is operated by a verified,
identifiable party that can be held responsible for its actions and exposes a
recourse/revocation path.

**Does NOT measure.** Runtime behavior, output quality, or financial statements of
the operator — only the *accountability* of the controlling entity.

**Inputs (observation schema).**
```json
{ "verified": true, "level": "DV | OV | EV" }
```
Derived from the identity-assurance tier of the controlling organization on the
agent's certificate / AgentCert (Domain-, Organization-, or Extended-Validation),
plus whether a liable legal entity and a published revocation path exist.

**Function (deterministic).**

| Observation | Raw score |
|---|---|
| `verified = false` | 0 |
| `EV` | 100 |
| `OV` | 75 |
| `DV` | 40 |

**Risk codes.** `SOLVENCY_OPERATOR_UNVERIFIED` (unverified), `SOLVENCY_OPERATOR_UNKNOWN`
(no observation).

**Evidence.** The X.509 / AgentCert validation record referenced by `evidenceUrl`.

---

## 2. `trustscore.behavior` — Operational Reliability

**Dimension:** `behavior`

**Definition.** The extent to which the agent does what it advertises, correctly
and consistently, under test.

**Does NOT measure.** Subjective helpfulness or tone — only measured task
correctness and stability.

**Inputs (observation schema).**
```json
{ "score": 0 }   // integer 0..100
```
The `score` is TrustModel's independent behavior score: a normalized mean of
measured sub-scores — capability/accuracy pass rate, consistency across repeated
runs (reliability), degradation under input perturbation / adversarial rephrasing
(robustness), and output-vs-claim faithfulness. Evaluated at temperature 0 with
multi-judge scoring and judge fingerprinting (no single-judge scoring).

**Function.** Passthrough of the validated `score` (0..100).

**Risk codes.** `BEHAVIOR_TRUSTSCORE_LOW` (score < 70), `BEHAVIOR_TRUSTSCORE_UNKNOWN`
(no observation).

**Evidence.** Evaluation run IDs + report referenced by `evidenceUrl`.

---

## 3. `trustscore.safety` — Harm Resistance

**Dimension:** `safety`

**Definition.** The agent's resistance to producing unsafe, non-compliant, or
privacy-violating output under normal and adversarial input.

**Does NOT measure.** Content style — only violation rates.

**Inputs (observation schema).**
```json
{ "score": 0 }   // integer 0..100
```
The `score` is TrustModel's independent safety score: a composite of
`100 − normalized violation rate` across safety-violation categories
(harmful/toxic), PII / data-leakage rate, prompt-injection / jailbreak resistance
from red-team probes, and applicable regulatory checks. Failures are counted as
signal.

**Function.** Passthrough of the validated `score` (0..100).

**Risk codes.** `SAFETY_TRUSTSCORE_LOW` (score < 70), `SAFETY_TRUSTSCORE_UNKNOWN`
(no observation).

**Evidence.** Red-team probe + evaluation results referenced by `evidenceUrl`.

---

## Versioning

These are **v0** reference definitions. Signal IDs, observation schemas, and the
solvency score map are stable within a major version; threshold constants
(e.g. the `< 70` risk cutoff) may be tuned in minor revisions and are documented
here rather than hard-coded assumptions. Any provider can implement the same
`port.Signal` contract against these definitions.
