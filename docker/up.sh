#!/usr/bin/env bash

echo "Building, (re)creating, starting, and attaching to containers for a service."

DIR=`dirname "$0"`
docker-compose --project-directory ./ --file docker-compose.yml up --detach --build