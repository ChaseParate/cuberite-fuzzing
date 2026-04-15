# Fuzzing [Cuberite](https://cuberite.org/)
## by [Chase Harkcom](https://github.com/ChaseParate) and [Max Petersen](https://github.com/GuyWithaPC)

See [implemented_serverbound_packets.md](implemented_serverbound_packets.md) to see which packets we have implemented.

## Development
Make sure to also pull the `cuberite` submodule (either pass `--recurse-submodules` to your `git clone` command or run `git submodule update --init`).
Run `make build-cuberite` at the root directory to build Cuberite.

### [boofuzz](https://boofuzz.readthedocs.io/en/stable/) Harnesses
Currently, all our code (including harnesses) is stored in the `fuzzing` directory.

Run `make fuzz` to run the fuzzer.

We use `ruff` for formatting and linting.
You can run `uvx pre-commit install` to install the formatting and linting pre-commit hooks. Alternatively, you can run `make format` to do said formatting and linting manually.

Run `make test` to run our unit tests.

## Bugs
- There seems to be an issue with Cuberite not properly disconnecting players, leading to players being kicked due to the server being too full. We mitigated this by just increasing the max player count (see [cuberite-config/settings.ini](cuberite-config/settings.ini)).
    - We noticed the `cServer::m_Clients` field properly reflects the number of connected players, but `cServer::m_PlayerCount` grows unbounded.
    - See: https://github.com/cuberite/cuberite/issues/5640
- An actual "packet of doom": https://github.com/cuberite/cuberite/issues/5640
