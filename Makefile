.PHONY: test test-unit up down build

build:
	docker compose build

test-unit:
	docker compose build test-unit
	docker compose --profile unit run --rm --no-deps test-unit

test: build
	docker compose --profile unit run --rm --no-deps test-unit
	docker compose up --abort-on-container-exit --exit-code-from test-int origin tornet client test-int

up: build
	docker compose up origin tornet client

down:
	docker compose down
