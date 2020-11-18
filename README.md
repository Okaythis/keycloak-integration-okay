# Okay Keycloak extension 

This repository contains development of a set of authenticator extensions for enhancing authentication capabilities with Keycloak ith Okay mobile app.

## Current Support Level

Current version extensions support Keycloak 11.0.2

### Installing Okay extension on Keycloak 

Since you might have Keycloak running, let’s shut it down for now

```
sudo systemctl stop keycloak.service
```

Now that Keycloak has stopped, let’s clone the repository

```
git clone https://github.com/Okaythis/keycloak-integration-okay && cd keycloak-integration-okay
```

Inside the directory, compile the project using this Maven command

```
mvn clean install
```

The build process creates a Keycloak compatible extension packaged in an EAR file with the Okay authenticator extensions. The EAR file should be placed into the `<KEYCLOAK_HOME>/standalone/deployments` directory and will be deployed automatically when the server is started.
To achieve this run the following script, that deploys the EAR file

```
sudo ./deploy.sh
```

Now let’s start the Keycloak server

```
sudo systemctl start keycloak.service

```

### Testing locally with Docker

After compiling you can test the deployment and Keycloak configuration using Docker, you run a docker compose file with

```
docker-compose up
```

Accessing the Keycloak Instance

By default, the deployed instance can be accessed on http://localhost:8080
