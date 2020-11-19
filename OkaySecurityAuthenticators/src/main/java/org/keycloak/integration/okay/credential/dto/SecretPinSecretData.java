package org.keycloak.integration.okay.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SecretPinSecretData {

    private final String pinCode;

    @JsonCreator
    public SecretPinSecretData(@JsonProperty("pinCode") String pinCode) {
        this.pinCode = pinCode;
    }

    public String getPinCode() {
        return pinCode;
    }
}
