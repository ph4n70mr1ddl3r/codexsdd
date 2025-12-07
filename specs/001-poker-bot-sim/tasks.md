# Tasks: Heads-up Poker Bot Simulation

**Input**: Design documents from `/specs/001-poker-bot-sim/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Not explicitly requested; maintain independent test criteria per story for manual/automated validation.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [ ] T001 Create source/test directories per plan in `src/{server,game,bots,common}` and `tests/{unit,integration,contract}`
- [ ] T002 Configure root `CMakeLists.txt` for C++20 targets `poker-server`, `bot-client`, and Catch2-enabled tests with Boost.Beast/Asio and nlohmann/json includes
- [ ] T003 [P] Add developer tooling configs (compiler warnings, sanitizers toggles) in `CMakeLists.txt` and `cmake/` includes to support fast iteration

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented  
**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T004 Define shared card/types and constants (ranks, suits, blind defaults, seat ids) in `src/common/types.hpp`
- [ ] T005 Implement JSON message models and serializers for `ClientMessage`/`ServerMessage` per contract in `src/common/messages.hpp`
- [ ] T006 Set up lightweight logging abstraction with stream sink and severity helpers in `src/common/logging.hpp`
- [ ] T007 Add Asio I/O context bootstrap and timer utility helpers for action deadlines in `src/server/runtime.hpp`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Two bots join and start a hand (Priority: P1) 🎯 MVP

**Goal**: Two bots connect over WebSocket, receive seats, and the server auto-starts the first hand once both seats are filled.

**Independent Test**: Connect two bot clients; verify `seat_assigned` and `hand_start` messages emit with blinds and button; dropping a seat before start pauses until replacement connects.

### Implementation for User Story 1

- [ ] T008 [P] [US1] Implement `PlayerSession` lifecycle (connect/disconnect/timeout state, stack_bb) in `src/server/player_session.hpp`
- [ ] T009 [P] [US1] Build WebSocket upgrade endpoint `/ws/table` with connection cap and keepalive in `src/server/websocket_server.cpp`
- [ ] T010 [US1] Handle bot registration (`register` messages) and seat assignment broadcasts in `src/server/websocket_server.cpp`
- [ ] T011 [US1] Implement `TableManager` to track two seats, gate hand start until both registered, and queue initial hand in `src/server/table_manager.cpp`
- [ ] T012 [US1] Emit `hand_start` with blinds, button seat, hole cards per seat using contract framing in `src/server/table_manager.cpp`

**Checkpoint**: User Story 1 functional and independently testable

---

## Phase 4: User Story 2 - Play out a NLHE hand (Priority: P2)

**Goal**: Run full NLHE hand with betting rounds, timeouts, legal action enforcement, and pot resolution via fold or showdown.

**Independent Test**: Drive one full hand via bot clients; confirm legal actions per prompt, timeout default actions applied, and pot awarded on fold or showdown with logged outcomes.

### Implementation for User Story 2

- [ ] T013 [P] [US2] Implement `Deck`/`Card` with shuffle/reset per hand in `src/game/deck.hpp`
- [ ] T014 [P] [US2] Build `Pot` tracking (contributions, side pots, outstanding amounts) in `src/game/pot.hpp`
- [ ] T015 [P] [US2] Create `HandState` machine (streets, action tracker, validation) in `src/game/hand.hpp`
- [ ] T016 [US2] Wire server hand loop to drive betting rounds, enforce legal actions/min raises, and apply timeout defaults in `src/server/hand_loop.cpp`
- [ ] T017 [US2] Evaluate showdown outcomes and split pots in `src/game/showdown.cpp`
- [ ] T018 [US2] Integrate server hand results with pot distribution and next-hand scheduling in `src/server/table_manager.cpp`
- [ ] T019 [US2] Update bot client to parse `action_request` and send random legal `action` payloads in `src/bots/bot_client.cpp`
- [ ] T020 [US2] Add structured hand logging (seating, actions, pots, outcomes) to support contract/acceptance checks in `src/common/logging.hpp`

**Checkpoint**: User Stories 1 AND 2 functional and independently testable

---

## Phase 5: User Story 3 - Ongoing bankroll management (Priority: P3)

**Goal**: Auto-reload stacks to 100BB whenever a bot reaches 5BB or less and maintain continuous multi-hand simulation.

**Independent Test**: Run repeated hands until a stack ≤5BB; verify reload to 100BB before next hand, blinds rotate correctly, and play continues without duplicate credits.

### Implementation for User Story 3

- [ ] T021 [P] [US3] Track pending reload flags and thresholds in `GameState` within `src/server/table_manager.cpp`
- [ ] T022 [US3] Apply reload adjustments between hands and log reload events per contract in `src/server/table_manager.cpp`
- [ ] T023 [US3] Ensure continuous hand loop with dealer rotation and reconnection handling for replacements in `src/server/table_manager.cpp`

**Checkpoint**: All user stories independently functional

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T024 [P] Harden validation and error responses for malformed messages in `src/common/messages.hpp`
- [ ] T025 [P] Add performance tuning for timers/IO context (hand throughput) in `src/server/runtime.hpp`
- [ ] T026 [P] Extend documentation with operational notes and log schema in `specs/001-poker-bot-sim/quickstart.md`
- [ ] T027 Final review and quickstart validation run (`cmake --build build && ctest`) to confirm end-to-end behaviors

---

## Dependencies & Execution Order

- Setup (Phase 1) → Foundational (Phase 2) → User Story phases in priority order (US1 → US2 → US3) → Polish.
- Within User Story 1: T008/T009 in parallel → T010 → T011 → T012.
- Within User Story 2: T013/T014/T015/T019/T020 in parallel → T016 → T017 → T018.
- Within User Story 3: T021 in parallel with validation hardening (T024) if desired → T022 → T023.

---

## Parallel Execution Examples

- **US1**: T008 and T009 can proceed together before coordinating seat assignment logic.
- **US2**: T013, T014, T015, T019, and T020 can run concurrently since they touch separate files (deck, pot, hand state, bot client, logging).
- **US3**: T021 can start while US2 wraps up; T022 and T023 follow sequentially after reload state exists.

---

## Implementation Strategy

- MVP first: Deliver US1 end-to-end after Setup/Foundational to validate WebSocket flow and seating.
- Incremental: Add US2 hand logic next, keeping logs/contract framing consistent; then layer US3 reload loop.
- Validate after each story using the independent tests described; keep changes isolated per story to preserve testability.
