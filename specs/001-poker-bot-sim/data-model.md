# Data Model: Heads-up Poker Bot Simulation

## Entities

### PlayerSession
- Fields: `session_id`, `connection` (WebSocket handle), `seat` (dealer/button flag), `stack_bb`, `state` (connected/disconnected/timed_out), `pending_reload` (bool), `action_deadline`.
- Relationships: Linked to active `Hand` via seat assignment.
- Validation: `stack_bb` must be ≥0; only two seats; reconnect replaces prior connection for same seat.
- Transitions: `connected → active → disconnected` with timeout mapping to `timed_out` and default action.

### Hand
- Fields: `hand_id`, `button_seat`, `street` (preflop/flop/turn/river/showdown), `community_cards[0..5]`, `hole_cards[2 per seat]`, `pot_state`, `action_tracker`, `status` (in_progress/resolved).
- Relationships: Owns `Pot`; references `PlayerSession` seats; uses `Deck`.
- Validation: Deck shuffled before dealing; streets progress sequentially; showdown only when ≥1 active seat and no pending bets.
- Transitions: `in_progress` progresses per street until `resolved` via fold or showdown.

### Pot
- Fields: `main_pot`, `side_pots[]` with {cap, contributors}, `contributions[seat]`, `amount_outstanding`.
- Relationships: Owned by `Hand`.
- Validation: Contributions non-negative; side pots cap at all-in amounts; distribution matches contributions at resolution.
- Transitions: Updated after each bet/raise/call; frozen at showdown before evaluation.

### GameState
- Fields: `table_id`, `current_hand`, `pending_reload_queue`, `dealer_rotation`, `blinds` (SB/BB), `hand_history_ids`.
- Relationships: Maintains lifecycle of hands and links to sessions.
- Validation: Exactly two seats tracked; blinds applied each hand with alternating dealer; reloads applied between hands only.
- Transitions: After each `Hand` resolution, applies reloads, rotates dealer, and spawns next `Hand`.

### Deck/Card
- Fields: `cards[52]`, `rng_seed`, `position`.
- Relationships: Used by `Hand` for dealing.
- Validation: 52 unique cards; reshuffle before each hand; position increments only forward.
- Transitions: `shuffled → dealing → exhausted/reset` per hand.
