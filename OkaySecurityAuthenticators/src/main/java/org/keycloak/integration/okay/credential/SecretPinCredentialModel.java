package org.keycloak.integration.okay.credential;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.integration.okay.credential.dto.SecretPinSecretData;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class SecretPinCredentialModel extends CredentialModel {
    public static final String TYPE = "SECRET_PIN";
    public static final String USER_LABEL = "Okay secret PIN";

    private final SecretPinSecretData secretData;

    private SecretPinCredentialModel(SecretPinSecretData secretData) {
        this.secretData = secretData;
    }

    private SecretPinCredentialModel(String answer) {
        secretData = new SecretPinSecretData(answer);
    }

    public static SecretPinCredentialModel createSecretPin(String answer) {
        SecretPinCredentialModel credentialModel = new SecretPinCredentialModel(answer);
        credentialModel.fillCredentialModelFields();
        credentialModel.setUserLabel(USER_LABEL);
        return credentialModel;
    }

    public static SecretPinCredentialModel createFromCredentialModel(CredentialModel credentialModel){
        try {
            SecretPinSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), SecretPinSecretData.class);

            SecretPinCredentialModel secretPinCredentialModel = new SecretPinCredentialModel(secretData);
            secretPinCredentialModel.setUserLabel(credentialModel.getUserLabel());
            secretPinCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            secretPinCredentialModel.setType(TYPE);
            secretPinCredentialModel.setId(credentialModel.getId());
            secretPinCredentialModel.setSecretData(credentialModel.getSecretData());
            return secretPinCredentialModel;
        } catch (IOException e){
            throw new RuntimeException(e);
        }
    }

    public SecretPinSecretData getSecretPinSecretData() {
        return secretData;
    }

    private void fillCredentialModelFields(){
        try {
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
