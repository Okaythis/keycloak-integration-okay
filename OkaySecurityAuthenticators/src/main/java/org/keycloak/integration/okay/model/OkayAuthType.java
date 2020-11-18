package org.keycloak.integration.okay.model;

public enum OkayAuthType {

    AUTH_OK(101),
    AUTH_PIN(102),
    AUTH_PIN_TAN(103),
    AUTH_BIOMETRIC_OK(105),
    GET_PAYMENT_CARD(111);

    private final int authCode;

    OkayAuthType(final int authCode) {
        this.authCode = authCode;
    }

    public int getAuthCode() { return authCode; }

    @Override
    public String toString() {
        return String.valueOf(authCode);
    }

    public String getName() {
        return this.name();
    }
}
