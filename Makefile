FUZZING_DIRECTORY := fuzzing

.PHONY: fuzz test format build-cuberite

fuzz:
	uv run -m $(FUZZING_DIRECTORY)

test:
	uv run pytest $(FUZZING_DIRECTORY)

format:
	uvx ruff check --fix $(FUZZING_DIRECTORY) && uvx ruff format $(FUZZING_DIRECTORY)

build-cuberite:
	-mkdir cuberite/build
	cd cuberite/build && cmake .. && make -j
