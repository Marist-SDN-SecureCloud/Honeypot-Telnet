

# Telnet-Honeypot

### Authors

**Eric Wedaa** - *Original Honeypot Creation* - [wedaa](https://github.com/wedaa)

**Daniel Gisolfi** - *Docker implementation and TCP Stream Addition* - [dgisolfi](https://github.com/dgisolfi)

## Overview

This honeypot is a custom implementation of a telnet dameon which has been modified to always reject username and password attempts but logs the attempts. Building on what Eric Wedaa created I have added a TCP Stream to capture attacks in realtime from the honeypot and forward them to a python server for parsing, analyzing, etc. Additionally, I have created a Docker image for the honeypot to allow for quick deployment on a server.

## Deployment

To deploy the honeypot using docker, the included make file can be used. Run `make` in the root of the repository to clean, build and run the honeypot from source.

### Docker Compose

Alternatively, docker compose can be used, to do so move the `docker-compose.yaml` file found in the root of the directory to the host machine and run:

```
docker-compose up
```
