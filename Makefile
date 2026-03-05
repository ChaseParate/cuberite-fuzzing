FUZZING_DIRECTORY := fuzzing

.PHONY: build-cuberite fuzz test

build-cuberite:
	-mkdir cuberite/build
	cd cuberite/build && cmake .. && make -j

fuzz:
	uv run -m $(FUZZING_DIRECTORY)

test:
	uv run pytest $(FUZZING_DIRECTORY)
