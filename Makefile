.PHONY: install build test lint dev

install:
	./scripts/install.sh

build:
	npm run build
	npm --prefix sdk/typescript run build

test:
	./scripts/test.sh

lint:
	npm run lint

dev: build
	npm start
