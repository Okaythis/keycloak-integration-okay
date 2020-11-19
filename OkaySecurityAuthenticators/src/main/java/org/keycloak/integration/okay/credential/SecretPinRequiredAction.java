package org.keycloak.integration.okay.credential;

import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;

import javax.ws.rs.core.Response;

public class SecretPinRequiredAction implements RequiredActionProvider, CredentialRegistrator {
    public static final String PROVIDER_ID = "secret_pin_config";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form().createForm("secret-pin-config.ftl");
        context.challenge(challenge);

    }

    @Override
    public void processAction(RequiredActionContext context) {
        String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst("secret_answer"));
        SecretPinCredentialProvider sqcp = (SecretPinCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "secret-question");
        sqcp.createCredential(context.getRealm(), context.getUser(), SecretPinCredentialModel.createSecretPin(answer));
        context.success();
    }

    @Override
    public void close() {

    }
}
