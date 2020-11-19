package org.keycloak.integration.okay.rest;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.integration.okay.model.OkayAuthType;
import org.keycloak.integration.okay.utils.OkayLoggingUtilities;

import java.io.IOException;

public class OkayRestClient {

    private static final Logger logger = Logger.getLogger(OkayRestClient.class);

    private final String OKAY_URI;
    private final Long tenantId;
    private final String tenantSecretToken;

    public OkayRestClient(String okay_uri, Long tenantId, String tenantSecretToken) {
        this.OKAY_URI = okay_uri;
        this.tenantId = tenantId;
        this.tenantSecretToken = tenantSecretToken;
    }

    public String linkUser(final String userExternalId) {

        final String methodName = "linkUser";
        OkayLoggingUtilities.entry(logger, methodName, userExternalId);

        String url = OKAY_URI + "/gateway/link";

        String signature = OkayUtilities.generateSignature(tenantId + userExternalId + tenantSecretToken);

        String json = String.format("{\"tenantId\": \"%s\", \"userExternalId\": \"%s\", \"signature\": \"%s\"}",
                tenantId, userExternalId, signature);

        OkayLoggingUtilities.print(logger, "link: "+ json);

        return httpPost(url, json);
    }

    public String authUser(final String userExternalId,
                           final OkayAuthType type,
                           final String header,
                           final String text) {


        String url = OKAY_URI + "/gateway/auth";

        String signature = OkayUtilities.generateSignature(
                tenantId
                + userExternalId
                + header
                + text
                + type
                + tenantSecretToken);

        String json = String.format(
                "{\"tenantId\": \"%s\", \"userExternalId\": \"%s\", \"type\": \"%s\", " +
                        "\"authParams\": {\"guiText\": \"%s\", \"guiHeader\": \"%s\"}," +
                        "\"signature\": \"%s\"}",
                tenantId, userExternalId, type.getName(), text, header, signature);

        OkayLoggingUtilities.print(logger, "json " +json);

        return httpPost(url, json);
    }

    public String checkStatus(final String session) {

        final String methodName = "checkStatus";
        OkayLoggingUtilities.entry(logger, methodName, session);

        String url = OKAY_URI + "/gateway/check";

        String signature = OkayUtilities.generateSignature(tenantId + session + tenantSecretToken);

        String json = String.format("{\"tenantId\": \"%s\", \"sessionExternalId\": \"%s\", \"signature\": \"%s\"}",
                tenantId, session, signature);

        return httpPost(url, json);

    }

    public String httpPost(String url, String json) {
        final String methodName = "httpPost";
        OkayLoggingUtilities.entry(logger, methodName);

        CloseableHttpClient client = null;
        String result = null;
        try {
            client = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url);

            StringEntity entity = new StringEntity(json);
            httpPost.setEntity(entity);

            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");
            CloseableHttpResponse response = client.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            EntityUtils.consume(response.getEntity());

            if (statusCode != 200) {
                OkayLoggingUtilities.error(logger, methodName, String.format("%s: %s", statusCode, responseBody));
            }
            OkayLoggingUtilities.print(logger,"response: "+ responseBody);
            result = responseBody;

            response.close();

        } catch (IOException e) {
            e.printStackTrace();
        }  if (client != null) {
            try {
                client.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        OkayLoggingUtilities.exit(logger, methodName, result);

        return result;
    }
}