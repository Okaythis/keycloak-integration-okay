#!/bin/bash


rm -rf /opt/keycloak/standalone/deployments/okay*

cp okay-integration/target/okay-integration.ear /opt/keycloak/standalone/deployments/

chmod 755 /opt/keycloak/standalone/deployments/okay-integration.ear

chown keycloak:keycloak /opt/keycloak/standalone/deployments/okay-integration.ear
