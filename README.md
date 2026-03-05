# Fuzzing [Cuberite](https://cuberite.org/)
## by [Chase Harkcom](https://github.com/ChaseParate) and [Max Petersen](https://github.com/GuyWithaPC)

The `cuberite` submodule is set to the head of their `experimental` branch as of 2026-03-01.

## Development
Make sure to also pull the `cuberite` submodule (either pass `--recurse-submodules` to your `git clone` command or run `git submodule update --init`).
Run `make build-cuberite` at the root directory to build Cuberite.

### [boofuzz](https://boofuzz.readthedocs.io/en/stable/) Harnesses
Currently, all our fuzzing harnesses are stored in "fuzzer".
Run `uv sync` to install all dependencies.

**TODO: Put any relevant fuzzer instructions here!**

We use `ruff` for formatting and linting.
You can run `uvx pre-commit install` to install the formatting and linting pre-commit hooks. Alternatively, you can run `uvx ruff check --fix && uvx ruff format` to do said formatting and linting manually.
