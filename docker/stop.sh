#!/usr/bin/env bash

echo Stopping running containers without removing them.

DIR=`dirname "$0"`
docker-compose --project-directory ./ --file docker-compose.yml stop