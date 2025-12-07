# Research Notes: Heads-up Poker Bot Simulation

## Library and Platform Choices

- Decision: Target C++20 with CMake build; rely on standard chrono/random for timers and shuffling.  
  Rationale: C++20 provides chrono utilities and stronger type safety while remaining broadly supported on Linux toolchains.  
  Alternatives considered: C++17 (lacks some convenience and ranges), Rust/Go (diverges from C++ requirement).

- Decision: Use Boost.Asio/Beast for WebSocket server and timeouts.  
  Rationale: Mature C++ WebSocket + timer support, integrates with Asio execution model for managing two concurrent sockets and action deadlines.  
  Alternatives considered: WebSocket++ (less actively maintained, more boilerplate), custom TCP framing (higher effort, less safety).

- Decision: Use nlohmann/json for message encoding/decoding.  
  Rationale: Lightweight header-only library with idiomatic C++ value mapping; easy schema validation with manual guards; no external runtime.  
  Alternatives considered: RapidJSON (faster but more verbose), Boost.PropertyTree (not true JSON and weaker schema support).

- Decision: Use Catch2 for unit/contract tests and scripted WebSocket clients for integration.  
  Rationale: Catch2 is header-only, easy assertions for value-heavy game logic; integration harness can drive real WebSocket frames to hit timeout/reload flows.  
  Alternatives considered: GoogleTest (heavier dependency), ad-hoc test binaries (less structure and reporting).

## Gameplay/Protocol Clarifications

- Decision: Action timeout default to 1s; server applies `check` when legal else `fold` and broadcasts timeout outcome.  
  Rationale: Keeps simulation fast for automation while following "safe default" requirement; consistent deterministic fallback simplifies tests.  
  Alternatives considered: Auto-call minimum bet (risks unintended pot growth), retry window (adds complexity without user benefit).

- Decision: WebSocket upgrade endpoint at `/ws/table`; JSON payloads include `type` discriminator with versioned schema.  
  Rationale: Single table simplifies routing; explicit type field enables contract validation and future evolution without breaking clients.  
  Alternatives considered: Separate endpoints per seat (unnecessary complexity), binary frames (no JSON, conflicts with spec).
