# Implementation Plan: Heads-up Poker Bot Simulation

**Branch**: `001-poker-bot-sim` | **Date**: 2025-12-07 | **Spec**: /home/riddler/codexsdd/specs/001-poker-bot-sim/spec.md
**Input**: Feature specification from /home/riddler/codexsdd/specs/001-poker-bot-sim/spec.md

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Build a C++20 simulation server that runs continuous heads-up no-limit hold'em via WebSocket JSON, orchestrating shuffling, blinds, betting rounds, action timeouts with safe defaults, and automatic reloads to 100BB whenever a bot stack drops to 5BB or less. Bots are thin WebSocket clients that send validated actions; the server holds all authority over state, resolves hands to fold or showdown, and emits structured logs for automated verification.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: C++20  
**Primary Dependencies**: Boost.Asio/Beast for WebSocket server + timers; nlohmann/json for JSON serialization; std random utilities for shuffle; lightweight logging via std::ostream abstraction  
**Storage**: In-memory only (single-table simulation)  
**Testing**: Catch2 unit tests; integration harness using scripted WebSocket clients to exercise full-hand flows and timeout defaults  
**Target Platform**: Linux server (portable POSIX build toolchain)  
**Project Type**: Single backend service with thin sample bot clients  
**Performance Goals**: Start first hand within 5 seconds of both bots connecting; sustain 100+ hands per minute for two seats without state corruption; 100% correct pot resolution on contract tests  
**Constraints**: Two concurrent client sockets; per-action timeout configurable (default sub-second) with deterministic fallback; side-pot accuracy and reload idempotence across hand boundaries  
**Scale/Scope**: Single heads-up table, continuous hands (100+ hand runs), unlimited bankroll via reload trigger at ≤5BB

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Constitution document is placeholder with no defined principles; no enforceable gates detected. Proceeding under default engineering discipline; update constitution separately when available.
- Post-design review: Current artifacts (research, data model, contracts) stay within single-service scope and require no governance exceptions; gate remains PASS.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
src/
├── server/              # WebSocket entrypoint, session management, timeouts
├── game/                # Deck, hand logic, betting rounds, pot tracking
├── bots/                # Thin bot client implementations for simulation
└── common/              # Shared utilities (logging, config, types)

tests/
├── unit/                # Deck, pot, hand-state unit tests (Catch2)
├── integration/         # WebSocket hand flows, reload and timeout scenarios
└── contract/            # Schema/serialization validation for message payloads
```

**Structure Decision**: Single-project layout rooted at /home/riddler/codexsdd/src with grouped domains for server, game logic, bots, and shared utilities; tests mirror unit/contract/integration scopes under /home/riddler/codexsdd/tests.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
