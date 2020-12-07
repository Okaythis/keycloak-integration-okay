package org.keycloak.integration.okay.auth.push;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.integration.okay.credential.SecretPinCredentialProvider;
import org.keycloak.integration.okay.credential.SecretPinCredentialProviderFactory;
import org.keycloak.integration.okay.rest.OkayUtilities;
import org.keycloak.integration.okay.utils.FormUtilities;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.keycloak.integration.okay.rest.OkayUtilities.DO_NOT_ACCEPT;
import static org.keycloak.integration.okay.rest.OkayUtilities.MINUS_ONE;
import static org.keycloak.integration.okay.rest.OkayUtilities.OK;
import static org.keycloak.integration.okay.rest.OkayUtilities.ONE_HUNDRED_ONE;
import static org.keycloak.integration.okay.rest.OkayUtilities.PUSH_NOTIFICATION_RESULT;
import static org.keycloak.integration.okay.rest.OkayUtilities.USER_NOT_LINKED;
import static org.keycloak.integration.okay.rest.OkayUtilities.ZERO;
import static org.keycloak.integration.okay.rest.OkayUtilities.isNumberValid;

public class OkayAuthenticator implements Authenticator, CredentialValidator<SecretPinCredentialProvider> {

    public static final String PUSH_NOTIFICATION_LOGIN_TEMPLATE = "push-notification-login.ftl";
    public static final String PUSH_NOTIFICATION_LOGIN_RESEND_TEMPLATE = "push-notification-login-resend.ftl";

    private static final String ACTION_PARAM = "action";
    private static final String AUTHENTICATE_PARAM = "authenticate";
    private static final String RESEND_PARAM = "resend";

    private final Logger logger = Logger.getLogger(OkayAuthenticator.class);

    public void authenticate(AuthenticationFlowContext context) {
        if (context.getAuthenticationSession().getAuthNote(OkayUtilities.PUSH_NOTIFICATION_SESSION_ID) == null) {
            initiatePushNotification(context);
        } else {
            Response challenge = context.form().createForm(PUSH_NOTIFICATION_LOGIN_TEMPLATE);
            context.challenge(challenge);
        }
    }

    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
        String action= formParams.getFirst(ACTION_PARAM);

        UserModel user = context.getUser();
        if (user == null) {
            context.challenge(FormUtilities.createErrorPage(context, new FormMessage("errorMsg2FARequired")));
            return;
        }

        if (RESEND_PARAM.equals(action)) {
            context.getAuthenticationSession().removeAuthNote(OkayUtilities.PUSH_NOTIFICATION_SESSION_ID);
            initiatePushNotification(context);
            return;
        }

        String pushNotificationState = OkayUtilities.getPushNotificationVerification(context);
        OkayLoggingUtilities.print(logger, "pushNotificationState: "+ pushNotificationState);

        if (AUTHENTICATE_PARAM.equals(action) && ZERO.equals(pushNotificationState)) {

            String result = context.getAuthenticationSession().getAuthNote(PUSH_NOTIFICATION_RESULT);
            OkayLoggingUtilities.print(logger, result);
            if (result != null) {

                if (result.equals(DO_NOT_ACCEPT)) {
                    context.forceChallenge(FormUtilities
                            .createErrorPage(context, new FormMessage("errorMsgAccessDenied")));
                    return;
                }

                boolean isNumeric = isNumberValid(result);
                if (isNumeric) {
                    boolean validated = validateAnswer(context, result);
                    OkayLoggingUtilities.print(logger, String.valueOf(validated));
                    if (!validated) {
                        context.challenge(FormUtilities.createErrorPage(context,
                                new FormMessage(AuthenticationFlowError.INVALID_CREDENTIALS.toString())));
                        return;
                    }
                }
            }

            context.success();
        } else if (AUTHENTICATE_PARAM.equals(action) && MINUS_ONE.equals(pushNotificationState)) {
            Response challenge = context.form().createForm(PUSH_NOTIFICATION_LOGIN_TEMPLATE);
            context.challenge(challenge);
        } else if (AUTHENTICATE_PARAM.equals(action) && ONE_HUNDRED_ONE.equals(pushNotificationState)) {
            Response challenge = context
                    .form()
                    .addError(new FormMessage("pushNotificationFormExpiredError"))
                    .createForm(PUSH_NOTIFICATION_LOGIN_RESEND_TEMPLATE);
            context.forceChallenge(challenge);
        } else {
            context
                    .forceChallenge(FormUtilities
                            .createErrorPage(context, new FormMessage("errorMsgAccessDenied")));
        }
    }

    public boolean requiresUser() {
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Hardcode to true for the time being
        // Only users with verify configured should use this authenticator
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No-op for the time being
    }

    public void close() {
        // No-op
    }

    private void initiatePushNotification(AuthenticationFlowContext context) {
        final String methodName = "initiatePushNotification";
        OkayLoggingUtilities.entry(logger, methodName, context);

        UserModel user = context.getUser();

        if (user != null) {

            String userId = user.getId();
            context.getAuthenticationSession().removeAuthNote(OkayUtilities.PUSH_NOTIFICATION_SESSION_ID);
            String response = OkayUtilities.auth(context,userId);
            if (response.equals(USER_NOT_LINKED)) {
                requireVerifyRegistration(context, methodName);
            } else if (response.equals(OK)) {
                //OkayUtilities.auth(context, userId);
                Response challenge = context.form().createForm(PUSH_NOTIFICATION_LOGIN_TEMPLATE);
                context.challenge(challenge);
                OkayLoggingUtilities.exit(logger, methodName);
            }
            return;

        } else {
            context.forceChallenge(FormUtilities.createErrorPage(context, new FormMessage("errorMsg2FARequired")));
        }
        OkayLoggingUtilities.exit(logger, methodName);
    }

    private void requireVerifyRegistration(AuthenticationFlowContext context, String methodName) {
        context.form().addError(new FormMessage("verifyRegistrationRequired"));
        context.attempted();
        OkayLoggingUtilities.exit(logger, methodName);
    }

    @Override
    public SecretPinCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (SecretPinCredentialProvider)session
                .getProvider(CredentialProvider.class, SecretPinCredentialProviderFactory.PROVIDER_ID);
    }

    protected boolean validateAnswer(AuthenticationFlowContext context, String pin) {
        String credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();

        UserCredentialModel input = new UserCredentialModel(credentialId, getType(context.getSession()), pin);
        return getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), input);
    }
}
