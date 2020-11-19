package org.keycloak.integration.okay.credential;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class SecretPinCredentialProviderFactory
        implements CredentialProviderFactory<SecretPinCredentialProvider> {

    public static final String PROVIDER_ID =  "secret-pin";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public SecretPinCredentialProvider create(KeycloakSession session) {
        return new SecretPinCredentialProvider(session);
    }
}
