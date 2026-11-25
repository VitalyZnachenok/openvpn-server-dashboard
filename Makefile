.PHONY: help build pull update up down restart logs clean shell tail-logs

help:
	@echo "OpenVPN Statistics Docker Management"
	@echo "===================================="
	@echo "make pull      - Pull the published image from Docker Hub"
	@echo "make update    - Pull the published image and restart on it"
	@echo "make build     - Build the image locally instead of pulling"
	@echo "make up        - Start services"
	@echo "make down      - Stop services"
	@echo "make restart   - Restart services"
	@echo "make logs      - View logs"
	@echo "make tail-logs - Follow last 100 log lines"
	@echo "make clean     - Clean up data"
	@echo "make shell     - Enter container shell"

build:
	docker compose build --no-cache

pull:
	docker compose pull

update: pull
	docker compose up -d

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

tail-logs:
	docker compose logs -f --tail=100
