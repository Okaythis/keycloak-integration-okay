package org.keycloak.integration.okay;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.integration.okay.rest.OkayUtilities;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

abstract public class AbstractOkayAuthenticatorFactory implements AuthenticatorFactory {


    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

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

    private final Logger logger = Logger.getLogger(AbstractOkayAuthenticatorFactory.class);

    abstract public String getDisplayType();

    abstract public Requirement[] getRequirementChoices();

    abstract public String getId();
    abstract public String getHelpText();


    public String getReferenceCategory() {
        final String methodName = "getReferenceCategory";
        OkayLoggingUtilities.entry(logger, methodName);

        String referenceCategory = null;

        OkayLoggingUtilities.exit(logger, methodName, referenceCategory);
        return referenceCategory;
    }

    public boolean isConfigurable() {
        final String methodName = "isConfigurable";
        OkayLoggingUtilities.entry(logger, methodName);

        boolean isConfigurable = true;

        OkayLoggingUtilities.exit(logger, methodName, isConfigurable);
        return isConfigurable;
    }

    public boolean isUserSetupAllowed() {
        final String methodName = "isUserSetupAllowed";
        OkayLoggingUtilities.entry(logger, methodName);

        boolean isUserSetupAllowed = false;

        OkayLoggingUtilities.exit(logger, methodName, isUserSetupAllowed);
        return isUserSetupAllowed;
    }


    public List<ProviderConfigProperty> getConfigProperties() {
        final String methodName = "getConfigProperties";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayLoggingUtilities.exit(logger, methodName, CONFIG_PROPERTIES);
        return CONFIG_PROPERTIES;
    }

    abstract public Authenticator create(KeycloakSession keycloakSession);

    public void init(Config.Scope scope) {
        // no-op
        final String methodName = "init";
        OkayLoggingUtilities.entry(logger, methodName, scope);
        OkayLoggingUtilities.exit(logger, methodName);
    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // no-op
        final String methodName = "postInit";
        OkayLoggingUtilities.entry(logger, methodName, keycloakSessionFactory);
        OkayLoggingUtilities.exit(logger, methodName);
    }

    public void close() {
        // no-op
        final String methodName = "close";
        OkayLoggingUtilities.entry(logger, methodName);
        OkayLoggingUtilities.exit(logger, methodName);
    }
}
