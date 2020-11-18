package org.keycloak.integration.okay.auth.registration;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.integration.okay.AbstractOkayAuthenticatorFactory;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

public class VerifyRegistrationAuthenticationFactory extends AbstractOkayAuthenticatorFactory {

    public static final String ID = "verify-reg";
    private static final VerifyRegistrationAuthenticator SINGLETON = new VerifyRegistrationAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    private final Logger logger = Logger.getLogger(VerifyRegistrationAuthenticationFactory.class);

    public Authenticator create(KeycloakSession session) {
        final String methodName = "create";
        OkayLoggingUtilities.entry(logger, methodName, session);
        return SINGLETON;
    }

    public String getDisplayType() {
        final String methodName = "getDisplayType";
        OkayLoggingUtilities.entry(logger, methodName);

        String displayType = "Okay Verify Registration";

        OkayLoggingUtilities.exit(logger, methodName, displayType);
        return displayType;
    }

    public String getHelpText() {
        final String methodName = "getHelpText";
        OkayLoggingUtilities.entry(logger, methodName);

        String helpText = "Register with Okay. Requires an authenticated user in the current authentication context.";

        OkayLoggingUtilities.exit(logger, methodName, helpText);
        return helpText;
    }

    public String getId() {
        final String methodName = "getId";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayLoggingUtilities.exit(logger, methodName, ID);
        return ID;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        final String methodName = "getRequirementChoices";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayLoggingUtilities.exit(logger, methodName, REQUIREMENT_CHOICES);
        return REQUIREMENT_CHOICES;
    }

}