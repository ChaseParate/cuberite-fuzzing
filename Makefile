FUZZING_DIRECTORY := fuzzing

CUBERITE_DIRECTORY := cuberite
CUBERITE_BUILD_DIRECTORY := $(CUBERITE_DIRECTORY)/build
CUBERITE_BINARY := $(CUBERITE_BUILD_DIRECTORY)/Server/Cuberite

RUN_CUBERITE_DIRECTORY := /tmp/run-cuberite
RUN_CUBERITE_PORT := 25565

CUBERITE_CONFIG_SETTINGS := cuberite-config/*

.PHONY: fuzz test format format-check build-cuberite clean-cuberite run-cuberite

fuzz:
	rm -rf $(RUN_CUBERITE_DIRECTORY)
	uv run -m $(FUZZING_DIRECTORY) fuzz\
		--port $(RUN_CUBERITE_PORT)\
		--address localhost

test:
	uv run pytest $(FUZZING_DIRECTORY)

format:
	uv run ruff check --fix $(FUZZING_DIRECTORY) && uv run ruff format $(FUZZING_DIRECTORY)

format-check:
	uv run ruff check $(FUZZING_DIRECTORY) && uv run ruff format --check $(FUZZING_DIRECTORY)

type-check:
	uv run ty check $(FUZZING_DIRECTORY)

# -------------------------------

$(CUBERITE_BUILD_DIRECTORY)/Makefile:
	mkdir -p $(CUBERITE_BUILD_DIRECTORY)
	cd $(CUBERITE_BUILD_DIRECTORY) && cmake -DCMAKE_BUILD_TYPE=RELEASE -DCMAKE_C_FLAGS='-fsanitize=address -g' -DCMAKE_CXX_FLAGS='-fsanitize=address -g' ..

$(CUBERITE_BINARY): $(CUBERITE_BUILD_DIRECTORY)/Makefile
	make -C $(CUBERITE_BUILD_DIRECTORY) -j

build-cuberite: $(CUBERITE_BINARY)

clean-cuberite:
	-rm -r $(CUBERITE_BUILD_DIRECTORY)

run-cuberite: build-cuberite
	mkdir -p $(RUN_CUBERITE_DIRECTORY)
	cp -r $(CUBERITE_CONFIG_SETTINGS) $(RUN_CUBERITE_DIRECTORY)
	cd $(RUN_CUBERITE_DIRECTORY) && $(abspath $(CUBERITE_BINARY)) -p $(RUN_CUBERITE_PORT)
