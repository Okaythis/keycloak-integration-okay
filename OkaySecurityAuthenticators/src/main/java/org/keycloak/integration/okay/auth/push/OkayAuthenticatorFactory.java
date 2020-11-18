package org.keycloak.integration.okay.auth.push;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.integration.okay.rest.OkayUtilities;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class OkayAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "push-login-authenticator";
    private static final OkayAuthenticator SINGLETON = new OkayAuthenticator();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE
    };


    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(OkayUtilities.CONFIG_CLIENT_TENANT_ID);
        property.setLabel("Tenant Identifier");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The ID of your Okay tenant");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(OkayUtilities.CONFIG_CLIENT_BASE_URL);
        property.setLabel("Okay API base URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Base URL from your Okay instance");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(OkayUtilities.CONFIG_CLIENT_SECRET);
        property.setLabel("API Client Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Client Secret from your Okay API Client");
        property.setSecret(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(OkayUtilities.CONFIG_CLIENT_AUTH);
        property.setLabel("Auth Type");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Authentication type used by Okay API Client");
        property.setSecret(true);
        CONFIG_PROPERTIES.add(property);
    }


    private Logger logger = Logger.getLogger(OkayAuthenticatorFactory.class);

    public String getDisplayType() {
        return "Okay Push Notification Login Authenticator";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
       return true;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getHelpText() {
        return "Send a push notification to your Okay Mobile App";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public Authenticator create(KeycloakSession session) {
        final String methodName = "create";
        OkayLoggingUtilities.entry(logger, methodName, session);
        return SINGLETON;
    }

    public void init(Config.Scope scope) {
    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    public void close() {
        // no-op
    }

    public String getId() {
        return ID;
    }
}
