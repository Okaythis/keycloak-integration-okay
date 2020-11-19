package org.keycloak.integration.okay.credential;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

public class SecretPinCredentialProvider
        implements CredentialProvider<SecretPinCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(SecretPinCredentialProvider.class);

    protected KeycloakSession session;

    public SecretPinCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    private UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }


    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;
        }
        if (!input.getType().equals(getType())) {
            return false;
        }
        String challengeResponse = input.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }
        CredentialModel credentialModel = getCredentialStore()
                .getStoredCredentialById(realm, user, input.getCredentialId());
        SecretPinCredentialModel sqcm = getCredentialFromModel(credentialModel);
        return sqcm.getSecretPinSecretData().getPinCode().equals(challengeResponse);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;
        return !getCredentialStore().getStoredCredentialsByType(realm, user, credentialType).isEmpty();
    }

    @Override
    public CredentialModel createCredential(RealmModel realm,
                                            UserModel user,
                                            SecretPinCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return getCredentialStore().createCredential(realm, user, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    @Override
    public SecretPinCredentialModel getCredentialFromModel(CredentialModel model) {
        return SecretPinCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(SecretPinCredentialProviderFactory.PROVIDER_ID)
                .helpText("secret-pin-text")
                .removeable(false)
                .build(session);
    }

    @Override
    public String getType() {
        return SecretPinCredentialModel.TYPE;
    }
}