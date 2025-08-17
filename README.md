# Ban Evasion Detection

The code and [paper](paper.pdf) for my 2025 Bachelor's thesis "Anti-Cheat Ban Evasion Detection".

This is a proof-of-concept system designed to identify previously-banned players and prevent them from returning to the game when using an alternate account.

It consists of a client-side and server-side component. The client-side component fetches relevant hardware information from the system using a in-process DLL and a kernel driver.
The server-side component communicates with the client and maintains a list of identifiers to find returning players.

### Notable features

- Usage of Trusted Platform Module features to create an unspoofable identity (if TPM is available)
- Signing fingerprint hashes to prevent replay attacks (ex. with community hosted servers)
- Configurable confidence and trust score system to automate flagging and bans
- Various fingerprinting techniques:
  - Local network mac addresses
  - Monitor serial numbers
  - VPN detection
  - ...

### Files

| File                | Description                                                                                                                      |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `paper.pdf`         | The actual Bachelor's Thesis.                                                                                                    |
| `schema.sql`        | The SQL definition of the server-side stored data.                                                                               |
| `game/`             | Contains the C# code for the client and server components as well as the anticheat server logic.                                 |
| `anticheat_user/`   | Contains the C++ code for the anticheat client DLL.                                                                              |
| `anticheat_kernel/` | Contains the C++ code for the anticheat kernel driver. Warning: There may or may not be exploitable or OS crashing bugs present. |
