.PHONY: help build up down restart logs clean shell migrate

help:
	@echo "OpenVPN Statistics Docker Management"
	@echo "===================================="
	@echo "make build    - Build Docker images"
	@echo "make up       - Start services"
	@echo "make down     - Stop services"
	@echo "make restart  - Restart services"
	@echo "make logs     - View logs"
	@echo "make clean    - Clean up data"
	@echo "make shell    - Enter container shell"
	@echo "make migrate  - Run one-time DB migration"

build:
	docker compose build --no-cache

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

clean:
	docker compose down -v
	rm -rf data/*

shell:
	docker exec -it openvpn-stats /bin/bash

migrate:
	docker exec -it openvpn-stats python migrate.py

tail-logs:
	docker compose logs -f --tail=100
