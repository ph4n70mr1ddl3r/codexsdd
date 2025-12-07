# Feature Specification: Heads-up Poker Bot Simulation

**Feature Branch**: `001-poker-bot-sim`  
**Created**: 2025-12-07  
**Status**: Draft  
**Input**: User description: "Build a c++ simulation of a heads up poker game. All communications use websockets and json. The server will coordinate the game and handle the networking, timeouts, etc gracefully. The two players will be bots with random strategy but observe proper rules on nlhe. Both players start with 100 BB and will auto reload once they their stack go below 5BB. The server will wait until the 2 bots will join and will start shuffling and dealing the cards until it reaches showdown or if a player folds. The players will have unlimited funds, they can reload back to 100BB once they have 5BB or less. the player program will mainly be just moves and communication, the server has all the authority, just like how a typical online poker works. the player just play by the rules, they have no game logic influence, they are just thin clients of the game."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Two bots join and start a hand (Priority: P1)

Two autonomous bot clients connect via WebSocket, register at a heads-up table, and the server begins the hand once both seats are occupied.

**Why this priority**: Connection and seat confirmation is the gateway to all gameplay; without it no simulation occurs.

**Independent Test**: Connect two bots, observe seat assignment confirmations, and verify the server automatically starts the first hand without manual triggers.

**Acceptance Scenarios**:

1. **Given** the server is idle with an empty table, **When** two bots connect and identify themselves, **Then** both are seated and the server signals hand start with blinds posted.
2. **Given** both bots are seated, **When** either disconnects before the hand starts, **Then** the table remains idle and waits for a replacement connection before starting.

---

### User Story 2 - Play out a NLHE hand (Priority: P2)

The server runs a full no-limit Texas Hold'em hand with shuffled cards, blinds, betting rounds, and determines the winner through fold or showdown, using bots' random actions constrained by the rules.

**Why this priority**: Valid hand flow is the core behavior being simulated; it demonstrates rule enforcement and round progression.

**Independent Test**: Start a hand with two connected bots, capture actions and dealer messages, and confirm the hand ends in either a fold resolution or showdown with correct pot allocation.

**Acceptance Scenarios**:

1. **Given** a new hand with blinds posted, **When** betting rounds proceed and one bot folds, **Then** the remaining bot is awarded the pot immediately and the next hand is queued.
2. **Given** both bots remain through river, **When** cards are revealed at showdown, **Then** the best five-card hand is declared the winner or pot is split on ties.

---

### User Story 3 - Ongoing bankroll management (Priority: P3)

Stacks start at 100BB, drop through play, and automatically reload to 100BB whenever a stack reaches 5BB or less, allowing continuous simulation across many hands.

**Why this priority**: Ensures the simulation runs indefinitely without manual intervention or bankrupt states.

**Independent Test**: Drive repeated hands until a bot stack falls to 5BB, verify automatic top-up to 100BB, and confirm play continues into subsequent hands.

**Acceptance Scenarios**:

1. **Given** a bot’s stack hits 5BB after losing a pot, **When** the hand ends, **Then** the server auto-reloads that bot to 100BB before the next hand starts.
2. **Given** multiple reloads occur during long sessions, **When** reviewing state after each reload, **Then** previous hands remain settled and new hands start with fresh stacks without duplicating pots or cards.

---

### Edge Cases

- Bot disconnects mid-hand; server should time out or fold that seat and award the pot appropriately.
- Simultaneous all-in results in main and side pot calculation with correct split handling on ties.
- Bot sends invalid or out-of-turn action; server rejects it and enforces a default action (e.g., fold or check) after timeout.
- Deck exhaustion or shuffle errors between hands; server reshuffles cleanly before each new hand.
- Auto-reload trigger hits repeatedly in back-to-back hands; reloads should not double-credit or skip blinds.

### Assumptions

- Default big blind size is a single betting unit; blinds post every hand with alternating dealer.
- Action timeout uses a fixed short duration suitable for automation, after which a safe default (check if allowed, otherwise fold) is applied.
- Bots choose from legal actions only after server validation; randomness is uniform across allowed options per turn.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Server MUST accept two bot connections over WebSocket, confirm seat assignment, and block hand start until both seats are filled.
- **FR-002**: Server MUST announce hand start with shuffled deck, dealer/button position, and blinds posted at 100BB stack depth.
- **FR-003**: Server MUST run betting rounds (preflop, flop, turn, river) enforcing no-limit hold'em rules: legal actions, minimum raises, pot tracking, and side pot handling for all-in scenarios.
- **FR-004**: Server MUST enforce per-action timeouts and apply a default safe action (check when legal, otherwise fold) when a bot fails to act in time.
- **FR-005**: Server MUST determine hand resolution through fold or showdown, evaluate hands, and distribute the pot (including split pots on ties) before starting the next hand.
- **FR-006**: Server MUST auto-reload any bot stack to 100BB at hand end whenever its balance is 5BB or less, allowing unlimited bankroll replenishment.
- **FR-007**: Server MUST send and receive all game events and actions as JSON messages over WebSocket, rejecting malformed messages without corrupting game state.
- **FR-008**: Server MUST maintain a continuous loop of hands while both bots remain connected, re-seating replacements if a bot reconnects after disconnection.
- **FR-009**: Server MUST log or emit state changes per hand (seating, actions, pots, reloads, outcomes) so test harnesses can verify correctness without manual inspection.

### Key Entities *(include if feature involves data)*

- **Player Session**: Represents a connected bot seat, including stack size, seat position (dealer/small blind), and connection status.
- **Hand**: Represents a single deal with deck state, community cards, hole cards per seat, betting round progression, and final outcome.
- **Pot**: Tracks contributions per seat, side pots, and distribution results after resolution.
- **Game State**: Table-level state including current blinds, dealer rotation, pending reload flags, and hand history references.
- **Card/Deck**: Standard 52-card deck representation used for shuffling and dealing each hand.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Two bots can connect and start the first hand within 5 seconds of both sockets opening, with correct blind assignment logged.
- **SC-002**: At least 95% of hands in a 100-hand automated run complete without invalid message errors or stalled timeouts.
- **SC-003**: Pot distribution accuracy reaches 100% across test cases covering fold wins, showdowns, ties, and side pots as verified by hand histories.
- **SC-004**: Auto-reload executes within one hand transition whenever a stack reaches 5BB or less, with no duplicated credits in 100 simulated reload events.
