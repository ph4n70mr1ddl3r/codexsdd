# Quickstart: Heads-up Poker Bot Simulation

1) Prereqs: C++20 toolchain (g++/clang++), CMake, Boost (Beast/Asio) headers, Catch2, nlohmann/json (header-only).  
2) Build: `cmake -S . -B build && cmake --build build`. Target binaries: `poker-server`, `bot-client`, test runners.  
3) Run server: `./build/poker-server --port 8080 --timeout-ms 1000 --reload-threshold-bb 5`. Server listens at `/ws/table` for upgrades.  
4) Run bots: `./build/bot-client --url ws://localhost:8080/ws/table --name botA` (repeat for second bot). Bots send random legal actions validated by server prompts.  
5) Observe: Server logs JSON events for seating, hands, actions, pots, and reloads; integration tests can parse logs to verify acceptance scenarios.  
6) Test: `ctest --test-dir build` runs unit, contract, and integration suites including timeout/reload cases.
