package org.keycloak.integration.okay.auth.registration;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.integration.okay.rest.OkayUtilities;
import org.keycloak.integration.okay.utils.FormUtilities;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.keycloak.integration.okay.auth.push.OkayAuthenticator.PUSH_NOTIFICATION_LOGIN_RESEND_TEMPLATE;
import static org.keycloak.integration.okay.auth.push.OkayAuthenticator.PUSH_NOTIFICATION_LOGIN_TEMPLATE;

public class VerifyRegistrationAuthenticator implements Authenticator {

    private static final String VERIFY_REGISTRATION_TEMPLATE = "verify-registration.ftl";
    private static final String QR_CODE_ATTR_NAME = "qrCode";
    private static final String QR_CODE_NUMBER_ATTR_NAME = "qrCodeNumber";

    private static final String ACTION_PARAM = "action";
    private static final String REGISTER_ACTION = "register";
    private static final String AUTHENTICATE_PARAM = "authenticate";

    public static final String VERIFY_REG_VERIFIED = "verify.registration.verified";

    private final Logger logger = Logger.getLogger(VerifyRegistrationAuthenticator.class);

    public void action(AuthenticationFlowContext context) {

        final String methodName = "action";
        OkayLoggingUtilities.entry(logger, methodName, context);

        MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();

        String action= formParams.getFirst(ACTION_PARAM);

        if (AUTHENTICATE_PARAM.equals(action)) {

            String pushNotificationState = OkayUtilities.getPushNotificationVerification(context);
            OkayLoggingUtilities.print(logger, "pushNotificationState: "+ pushNotificationState);

            if ("0".equals(pushNotificationState)) {
                context.success();
            } else if ("-1".equals(pushNotificationState)) {
                Response challenge = context.form().createForm(PUSH_NOTIFICATION_LOGIN_TEMPLATE);
                context.challenge(challenge);
            } else if ("101".equals(pushNotificationState)) {
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
        } else if (REGISTER_ACTION.equals(action)) {
            // User has not yet cancelled the registration attempt. Let's poll for registration status
            initiateAndPoll(context);
        }

        OkayLoggingUtilities.exit(logger, methodName);
    }

    public void authenticate(AuthenticationFlowContext context) {
        final String methodName = "authenticate";
        OkayLoggingUtilities.entry(logger, methodName, context);
        initiateAndPoll(context);
        OkayLoggingUtilities.exit(logger, methodName);

    }

    private void initiateAndPoll(AuthenticationFlowContext context) {
        final String methodName = "initiateAndPoll";
        OkayLoggingUtilities.entry(logger, methodName, context);

        UserModel user = context.getUser();
        if (user != null) {

            String userId = user.getId();
            context.getAuthenticationSession().removeAuthNote(OkayUtilities.PUSH_NOTIFICATION_SESSION_ID);

            String response = OkayUtilities.auth(context,userId);

            if (response.equals("UserNotLinked")) {

                String qrCode = OkayUtilities.getVerifyRegistrationQrCode(context);

                if (qrCode == null) {
                    qrCode = OkayUtilities.getQrCode(context, userId);
                    OkayUtilities.setVerifyRegistrationQrCode(context, qrCode);
                }

                String qrCodeNumber = OkayUtilities.getVerifyRegistrationQrCodeNumber(context);

                Response challenge = context.form()
                        .setAttribute(QR_CODE_ATTR_NAME, qrCode)
                        .setAttribute(QR_CODE_NUMBER_ATTR_NAME, qrCodeNumber)
                        .createForm(VERIFY_REGISTRATION_TEMPLATE);
                context.challenge(challenge);

                OkayLoggingUtilities.exit(logger, methodName);

            }  else if (response.equals("OK")) {
                Response challenge = context.form().createForm(PUSH_NOTIFICATION_LOGIN_TEMPLATE);
                context.challenge(challenge);
                context.getSession().setAttribute(VERIFY_REG_VERIFIED, true);
            }

        } else {
            context.forceChallenge(FormUtilities
                    .createErrorPage(context, new FormMessage("errorMsgMissingEmailAndPhoneNumber")));
        }

        OkayLoggingUtilities.exit(logger, methodName);
    }

    public void close() {
        final String methodName = "close";
        OkayLoggingUtilities.entry(logger, methodName);
        // no-op
        OkayLoggingUtilities.exit(logger, methodName);
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        final String methodName = "configuredFor";
        OkayLoggingUtilities.entry(logger, methodName, session, realm, user);

        boolean configuredFor = true;

        OkayLoggingUtilities.exit(logger, methodName, configuredFor);
        return configuredFor;
    }

    public boolean requiresUser() {
        final String methodName = "requiresUser";
        OkayLoggingUtilities.entry(logger, methodName);

        boolean requiresUser = true;

        OkayLoggingUtilities.exit(logger, methodName, requiresUser);
        return requiresUser;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        final String methodName = "setRequiredActions";
        OkayLoggingUtilities.entry(logger, methodName, session, realm, user);
        // no-op
        OkayLoggingUtilities.exit(logger, methodName);
    }

}
