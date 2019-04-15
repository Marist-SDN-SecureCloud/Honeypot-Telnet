# Telnet Honeypot
# Author:  Daniel Nicolas Gisolfi

USER=dgisolfi
IMAGE=telnet_honeypot
CONTAINER=telnet_honeypot

MAKE:
	@make clean
	@make build
	@make run

intro:
	@echo "Telnet Honeypot v2.0\n"

clean:
	-docker kill $(CONTAINER)
	-docker rm $(CONTAINER)
	-docker rmi $(IMAGE)

build: intro
	@docker build -t $(IMAGE) .

dev: build
	@docker run -it --rm --name $(CONTAINER) -p23:23 -v$(PWD)/dev:/usr/local/source/ptelnetd/dev $(IMAGE)

# Run the honeypot and TCP server
run: build
	@docker run -it --rm --name $(CONTAINER) -p23:23 $(IMAGE)

# Push Docker image to Docker Hub
publish: build
	@docker tag $(IMAGE) $(USER)/$(IMAGE):tag
	@docker push $(USER)/$(IMAGE)

.PHONY: intro clean build run