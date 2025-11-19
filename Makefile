COMPOSE_FILE=docker-compose.yml
ENV_FILE=.env

include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE))

.PHONY: up down restart logs build clean pull ps health

up:
	@echo "Starting services..."
	@echo ${PCAP_MOUNTED_DIRECTORY}
	docker compose -f $(COMPOSE_FILE) up -d

down:
	@echo "Stopping services..."
	docker compose -f $(COMPOSE_FILE) down

restart:
	@echo "Restarting services..."
	docker compose -f $(COMPOSE_FILE) down
	docker compose -f $(COMPOSE_FILE) up -d

logs:
	@echo "Tailing logs..."
	docker compose -f $(COMPOSE_FILE) logs -f

build:
	@echo "Building images..."
	docker compose -f $(COMPOSE_FILE) build

pull:
	@echo "Pulling latest images..."
	docker compose -f $(COMPOSE_FILE) pull

ps:
	@echo "Service status:"
	docker compose -f $(COMPOSE_FILE) ps

health:
	@echo "Checking health of services..."
	@docker compose -f $(COMPOSE_FILE) ps --format '{{.Name}}: {{.Health}}'

clean:
	@echo "Removing containers, volumes, and networks..."
	docker compose -f $(COMPOSE_FILE) down -v --remove-orphans
