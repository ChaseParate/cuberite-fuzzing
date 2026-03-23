FUZZING_DIRECTORY := fuzzing

CUBERITE_DIRECTORY := cuberite
CUBERITE_BUILD_DIRECTORY := $(CUBERITE_DIRECTORY)/build
CUBERITE_BINARY := $(CUBERITE_BUILD_DIRECTORY)/Server/Cuberite

RUN_CUBERITE_DIRECTORY := /tmp/run-cuberite
RUN_CUBERITE_PORT := 25565

CUBERITE_CONFIG_SETTINGS := cuberite-config/settings.ini

.PHONY: fuzz test format format-check build-cuberite clean-cuberite run-cuberite

fuzz:
	uv run -m $(FUZZING_DIRECTORY)

test:
	uv run pytest $(FUZZING_DIRECTORY)

format:
	uvx ruff check --fix $(FUZZING_DIRECTORY) && uvx ruff format $(FUZZING_DIRECTORY)

format-check:
	uvx ruff check $(FUZZING_DIRECTORY) && uvx ruff format --check $(FUZZING_DIRECTORY)

# -------------------------------

$(CUBERITE_BUILD_DIRECTORY)/Makefile:
	mkdir -p $(CUBERITE_BUILD_DIRECTORY)
	cd $(CUBERITE_BUILD_DIRECTORY) && cmake ..

$(CUBERITE_BINARY): $(CUBERITE_BUILD_DIRECTORY)/Makefile
	make -C $(CUBERITE_BUILD_DIRECTORY) -j

build-cuberite: $(CUBERITE_BINARY)

clean-cuberite:
	-rm -r $(CUBERITE_BUILD_DIRECTORY)

run-cuberite: build-cuberite
	mkdir -p $(RUN_CUBERITE_DIRECTORY)
	cp $(CUBERITE_CONFIG_SETTINGS) $(RUN_CUBERITE_DIRECTORY)
	cd $(RUN_CUBERITE_DIRECTORY) && $(abspath $(CUBERITE_BINARY)) -p $(RUN_CUBERITE_PORT)
