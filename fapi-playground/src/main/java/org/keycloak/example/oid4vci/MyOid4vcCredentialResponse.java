package org.keycloak.example.oid4vci;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.testsuite.util.oauth.oid4vc.Oid4vcCredentialResponse;

import java.io.IOException;
import java.util.Map;

// Class to workaround throwing IllegalStateExceptions by Oid4vcCredentialResponse
public class MyOid4vcCredentialResponse {

    private final int statusCode;
    private final Map<String, String> headers;
    private final String error;
    private final String errorDescription;

    private final CredentialResponse credentialResponse;
    private final String encryptedCredentialResponse;

    public MyOid4vcCredentialResponse(Oid4vcCredentialResponse response) throws IOException {
        this.statusCode = response.getStatusCode();
        this.headers = response.getHeaders();
        this.error = response.getError();
        this.errorDescription = response.getErrorDescription();

        this.credentialResponse = computeCredentialResponse(response);
        this.encryptedCredentialResponse = computeEncryptedCredentialResponse(response);
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public CredentialResponse getCredentialResponse() {
        return credentialResponse;
    }

    public String getEncryptedCredentialResponse() {
        return encryptedCredentialResponse;
    }

    private CredentialResponse computeCredentialResponse(Oid4vcCredentialResponse response) {
        try {
            return response.getCredentialResponse();
        } catch (IllegalStateException ise) {
            return null;
        }
    }

    private String computeEncryptedCredentialResponse(Oid4vcCredentialResponse response) {
        try {
            return response.getEncryptedCredentialResponse();
        } catch (IllegalStateException ise) {
            return null;
        }
    }




}
