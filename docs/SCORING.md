# Scoring Model

This document defines telemetry-driven scoring for h3retik.

## 1) Campaign Ratings

## 1.1) OPSEC Rating

- Goal: estimate forensic trace burden from executed actions.
- Scale: `0..100` (higher is safer/cleaner).
- Built from telemetry command history, not UI clicks.

Computation shape:

- classify each executed command by behavior class (`control`, `evidence`, `passive`, `discovery`, `exploit`, `auth-attack`, `pivot`, `exfil`, `mutation`, `general`)
- accumulate trace burden from class deltas
- add penalties for failures, repeats, and high action volume
- final score: `opsec_rating = 100 - trace_burden`

Neutral controls:

- target set/info/start operations
- runtime up/down operations
- mode/scope switches and non-executing UI actions

These are intentionally neutral and do not count as compromise progression.

## 1.2) PWN Rating

- Goal: estimate confirmed compromise depth.
- Scale: `0..100` (higher means deeper verified compromise).
- Derived from telemetry-backed chain state + evidence depth.

Input dimensions:

- chain stages (`recon`, `breach`, `access`, `exfil`, `tamper`, `privesc`)
- high-value loot evidence (creds/tokens/db/artifacts)
- severity-weighted findings (`critical`, `high`)
- integrity-impact evidence when tamper is confirmed

## 2) Individual Action OPSEC Meter

The per-action OPSEC meter shown in TUI is telemetry-aware:

- baseline predicted risk from action semantics (`label/command/group/action id`)
- blended with observed risk from matching historical command telemetry (same action id pattern)

Result:

- if no history exists, meter uses predicted risk
- if history exists, meter converges toward observed behavior on this campaign

This makes the meter fit real execution context instead of static tags.

## 3) Dynamic, Target-Agnostic Behavior

Scoring is target-agnostic and telemetry-native:

- no dependency on Juice Shop-specific constants
- same model works across arbitrary targets as long as telemetry is emitted

## 4) Implementation Anchors

- Action classifier and deltas: `cmd/juicetui/main.go` (`ratingDeltasFromMeta`)
- Campaign ratings: `cmd/juicetui/main.go` (`exploitCampaignRatings`)
- Per-action predicted meter: `cmd/juicetui/main.go` (`actionOpsecScore`)
- Per-action telemetry-blended meter: `cmd/juicetui/main.go` (`actionEffectiveOpsecScore`)

## 5) Tuning Policy

When adjusting scoring:

1. update this document first,
2. update classification logic,
3. validate with `go test ./...`,
4. keep neutral controls neutral unless policy changes.

