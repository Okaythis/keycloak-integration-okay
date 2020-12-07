package org.keycloak.integration.okay.rest;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.integration.okay.model.OkayAuthType;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;
import org.keycloak.models.AuthenticatorConfigModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OkayUtilities {

    public static final String HASH = "SHA-256";

    public static final String PUSH_NOTIFICATION_AUTHENTICATOR_ID_ATTR_NAME = "push.notification.authenticator.id";
    public static final String PUSH_NOTIFICATION_SESSION_ID = "push.notification.session.id";
    public static final String PUSH_NOTIFICATION_RESULT = "push.notification.result";

    public static final String CONFIG_CLIENT_TENANT_ID = "tenant.id";
    public static final String CONFIG_CLIENT_BASE_URL = "base.url";
    public static final String CONFIG_CLIENT_SECRET = "client.secret";
    public static final String CONFIG_CLIENT_AUTH = "client.auth";
    public static final String AUTH_CLIENT_ID = "client.auth.id" ;

    public static final String ZERO = "0";
    public static final String MINUS_ONE = "-1";
    public static final String ONE_HUNDRED_ONE = "101";
    public static final String ONE_HUNDRED_TWO = "102";
    public static final String USER_NOT_LINKED = "UserNotLinked";
    public static final String OK = "OK";
    public static final String CODE_REGEX = "\"code\":\\s*([0-9\\-]+)";
    public static final String DATA_TYPE_REGEX = "\"dataType\":\\s*([0-9\\-]+)";
    public static final String DATA_REGEX = "\"data\":\\s*\"([^\"]+)\"";
    public static final String MESSAGE_REGEX = "\"message\":\\s*\"([^\"]+)\"";
    public static final String QR_REGEX = "\"linkingQrImg\":\\s*\"([^\"]+)\"";
    public static final String LINKING_CODE_REGEX = "\"linkingCode\":\\s*\"([^\"]+)\"";
    public static final String SESSION_REGEX = "\"sessionExternalId\":\\s*\"([^\"]+)\"";
    public static final String NUMBER_REGEX = "^\\d{4}$";
    public static final String DO_NOT_ACCEPT = "NO";

    public static final Pattern NUMBER_PATTERN = Pattern.compile(NUMBER_REGEX);
    public static final Pattern MESSAGE_PATTERN = Pattern.compile(MESSAGE_REGEX);
    public static final Pattern DATA_PATTERN = Pattern.compile(DATA_REGEX);
    public static final Pattern QR_PATTERN = Pattern.compile(QR_REGEX);
    public static final Pattern CODE_PATTERN = Pattern.compile(CODE_REGEX);
    public static final Pattern LINKING_CODE_PATTERN = Pattern.compile(LINKING_CODE_REGEX);
    public static final Pattern SESSION_PATTERN = Pattern.compile(SESSION_REGEX);


    private static final Logger logger = Logger.getLogger(OkayUtilities.class);

    private static final String guiText = "Do you okay this transaction";
    private static final String guiHeader = "Authorization requested";


    public static String getTenantHostname(AuthenticationFlowContext context) {
        final String methodName = "getTenantHostname";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String tenantHostname = null;
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();
        if (authenticatorConfigModel != null) {
            Map<String, String> authenticatorConfig = authenticatorConfigModel.getConfig();
            if (authenticatorConfig != null) {
                // Load tenant configuration
                tenantHostname = authenticatorConfig.get(OkayUtilities.CONFIG_CLIENT_TENANT_ID);
            }
        }

        OkayLoggingUtilities.exit(logger, methodName, tenantHostname);
        return tenantHostname;
    }

    public static String getClientBaseUrl(AuthenticationFlowContext context) {
        final String methodName = "getClientBaseUrl";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String baseUrl = null;
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();
        if (authenticatorConfigModel != null) {
            Map<String, String> authenticatorConfig = authenticatorConfigModel.getConfig();
            if (authenticatorConfig != null) {
                // Load tenant configuration
                baseUrl = authenticatorConfig.get(OkayUtilities.CONFIG_CLIENT_BASE_URL);
            }
        }

        OkayLoggingUtilities.exit(logger, methodName, baseUrl);
        return baseUrl;
    }

    public static String getAuthType(AuthenticationFlowContext context) {
        final String methodName = "getAuthType";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String auth = null;
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();
        if (authenticatorConfigModel != null) {
            Map<String, String> authenticatorConfig = authenticatorConfigModel.getConfig();
            if (authenticatorConfig != null) {
                // Load tenant configuration
                auth = authenticatorConfig.get(OkayUtilities.CONFIG_CLIENT_AUTH);
            }
        }

        context.getAuthenticationSession().setUserSessionNote(AUTH_CLIENT_ID, auth);

        OkayLoggingUtilities.exit(logger, methodName, auth);
        return auth;
    }

    public static String getConfigClientSecret(AuthenticationFlowContext context) {
        final String methodName = "getConfigClientSecret";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String clientSecret = null;
        AuthenticatorConfigModel authenticatorConfigModel = context.getAuthenticatorConfig();
        if (authenticatorConfigModel != null) {
            Map<String, String> authenticatorConfig = authenticatorConfigModel.getConfig();
            if (authenticatorConfig != null) {
                // Load tenant configuration
                clientSecret = authenticatorConfig.get(OkayUtilities.CONFIG_CLIENT_SECRET);
            }
        }

        OkayLoggingUtilities.exit(logger, methodName, clientSecret);
        return clientSecret;
    }

    public static String linking(AuthenticationFlowContext context, String userId) {

        final String methodName = "linking";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayRestClient okayRestClient = new OkayRestClient(
                getClientBaseUrl(context),
                Long.parseLong(getTenantHostname(context)),
                getConfigClientSecret(context));


        OkayLoggingUtilities.exit(logger, methodName);

        return okayRestClient.linkUser(userId);
    }

    public static String tryLink(AuthenticationFlowContext context, String userId) {
        String response = linking(context,userId);

        return regexMatch(response, MESSAGE_PATTERN);
    }

    public static String getVerifyRegistrationQrCode(AuthenticationFlowContext context) {
        final String methodName = "getVerifyRegistrationQrCode";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String result = context.getAuthenticationSession().getUserSessionNotes().get("verify.registration.qr");

        OkayLoggingUtilities.exit(logger, methodName, result);
        return result;
    }


    public static String getVerifyRegistrationQrCodeNumber(AuthenticationFlowContext context) {
        final String methodName = "getVerifyRegistrationQrCodeNumber";
        OkayLoggingUtilities.entry(logger, methodName, context);

        String result = context.getAuthenticationSession().getUserSessionNotes().get("verify.registration.qrNumber");

        OkayLoggingUtilities.exit(logger, methodName, result);
        return result;
    }

    public static void setVerifyRegistrationQrCode(AuthenticationFlowContext context, String qrCode) {
        final String methodName = "setVerifyRegistrationQrCode";
        OkayLoggingUtilities.entry(logger, methodName, context, qrCode);

        context.getAuthenticationSession().setUserSessionNote("verify.registration.qr", qrCode);

        OkayLoggingUtilities.exit(logger, methodName);
    }


    public static String getQrCode(AuthenticationFlowContext context, String userId) {
        String linkUserResponse = OkayUtilities.linking(context, userId);

        String qrCode = regexMatch(linkUserResponse, QR_PATTERN);

        String linkingCode = regexMatch(linkUserResponse,LINKING_CODE_PATTERN);

        context.getAuthenticationSession().setUserSessionNote("verify.registration.qrNumber", linkingCode);

        return qrCode;
    }

    public static String auth(AuthenticationFlowContext context, String userId) {

        final String methodName = "auth";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayRestClient okayRestClient = new OkayRestClient(
                getClientBaseUrl(context),
                Long.parseLong(getTenantHostname(context)),
                getConfigClientSecret(context));

        OkayLoggingUtilities.exit(logger, methodName);

        String authTypeStr = getAuthType(context);

        OkayAuthType authType = OkayAuthType.valueOf(authTypeStr);

        String response = okayRestClient.authUser(userId, authType, guiHeader, guiText);

        String sessionId = regexMatch(response, SESSION_PATTERN);

        String returnCode =  regexMatch(response, CODE_PATTERN);

        if (returnCode.equals(ZERO)) {
            context.getAuthenticationSession().setAuthNote(PUSH_NOTIFICATION_SESSION_ID, sessionId);
        }

        return regexMatch(response,MESSAGE_PATTERN);
    }

    public static String getPushNotificationVerification(AuthenticationFlowContext context) {
        String authenticatorId = context.getAuthenticationSession().getAuthNote(PUSH_NOTIFICATION_SESSION_ID);

        if (authenticatorId == null) {
            // TODO: Error!
        }

        String response = check(context, authenticatorId);

        String data = regexMatch(response, DATA_PATTERN);
        context.getAuthenticationSession().setAuthNote(PUSH_NOTIFICATION_RESULT, data);

        return regexMatch(response, CODE_PATTERN);
    }


    public static String check(AuthenticationFlowContext context, String sessionId) {

        final String methodName = "check";
        OkayLoggingUtilities.entry(logger, methodName);

        OkayRestClient okayRestClient = new OkayRestClient(
                getClientBaseUrl(context),
                Long.parseLong(getTenantHostname(context)),
                getConfigClientSecret(context));

        OkayLoggingUtilities.exit(logger, methodName);

        return okayRestClient.checkStatus(sessionId);
    }

    public static String generateSignature(String input) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(HASH);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] check = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(check), StandardCharsets.UTF_8);
    }

    private static String regexMatch(String input, Pattern extraction) {
        String result = null;
        Matcher matcher = extraction.matcher(input);
        if (matcher.find()) {
            result = matcher.group(1);
        }
        return result;
    }

    public static boolean isNumberValid(String strNum) {
        if (strNum == null) {
            return false;
        }
        return NUMBER_PATTERN.matcher(strNum).matches();
    }
}
