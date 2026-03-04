.PHONY: build-cuberite

build-cuberite:
	-mkdir cuberite/build
	cd cuberite/build && cmake .. && make -j
