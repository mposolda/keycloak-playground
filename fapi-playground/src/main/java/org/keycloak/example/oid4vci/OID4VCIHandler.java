package org.keycloak.example.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import jakarta.ws.rs.core.HttpHeaders;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OID4VCConstants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.example.Services;
import org.keycloak.example.bean.InfoBean;
import org.keycloak.example.handlers.ActionHandler;
import org.keycloak.example.handlers.ActionHandlerContext;
import org.keycloak.example.util.*;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailResponse;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsProcessor;
import org.keycloak.protocol.oid4vc.issuance.requiredactions.VerifiableCredentialOfferAction;
import org.keycloak.protocol.oid4vc.model.*;
import org.keycloak.protocol.oidc.grants.PreAuthorizedCodeGrantTypeFactory;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.testsuite.util.oauth.AbstractHttpPostRequest;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.oid4vc.CredentialOfferResponse;
import org.keycloak.testsuite.util.oauth.oid4vc.PreAuthorizedCodeGrantRequest;
import org.keycloak.util.AuthorizationDetailsParser;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.keycloak.OAuth2Constants.OPENID_CREDENTIAL;
import static org.keycloak.constants.OID4VCIConstants.VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID;
import static org.keycloak.example.util.MyConstants.REALM_NAME;

public class OID4VCIHandler implements ActionHandler {

    private static final Logger log = Logger.getLogger(OID4VCIHandler.class);

    static {
        AuthorizationDetailsParser.registerParser(OPENID_CREDENTIAL, new OID4VCAuthorizationDetailsProcessor.OID4VCAuthorizationDetailsParser());
    }

    @Override
    public Map<String, Function<ActionHandlerContext, InfoBean>> getActions() {
        return Map.of(
                "oid4vci-wellknown-endpoint", this::handleOID4VCIWellKnownEndpointAction,
                "oid4vci-authz-code-flow", this::handleAuthzCodeFlow,
                "oid4vci-pre-authz-code-flow", this::handleCreateCredentialOfferAction,
                "oid4vci-required-action", this::createRequiredAction,
                "oid4vci-pre-authz-code-with-offer", this::handlePreAuthzFlowWithOffer,
                "oid4vci-credential-request", this::credentialRequest,
                "oid4vci-last-credential-response", this::getLastCredentialResponse,
                "oid4vci-create-presentation", this::createPresentation
        );
    }

    @Override
    public void onAuthenticationCallback(SessionData session, AccessTokenResponse accessTokenResponse) {
        if (accessTokenResponse.getAuthorizationDetails() == null || accessTokenResponse.getAuthorizationDetails().isEmpty()) {
            return;
        }
        List<OID4VCAuthorizationDetailResponse> authzDetails = accessTokenResponse.getAuthorizationDetails()
                .stream()
                .map(authDetail -> authDetail.asSubtype(OID4VCAuthorizationDetailResponse.class))
                .toList();

        if (authzDetails.isEmpty()) {
            return;
        } else if (authzDetails.size() > 1) {
            throw new MyException("Unexpected size of the authzDetails. Size was " + authzDetails.size() + ". The response had authorization details: " + accessTokenResponse.getAuthorizationDetails());
        }
        OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
        oid4vciCtx.setAuthzDetails(authzDetails.get(0));

        oid4vciCtx.setAccessToken(accessTokenResponse.getAccessToken());
    }

    @Override
    public void onLogoutCallback(SessionData session) {
        OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
        oid4vciCtx.cleanup();
    }

    private InfoBean handleOID4VCIWellKnownEndpointAction(ActionHandlerContext actionContext) {
        CredentialIssuer credentialIssuer = invokeOID4VCIWellKnownEndpoint();

        OID4VCIContext oid4VCIContext = actionContext.getSession().getOrCreateOID4VCIContext();
        oid4VCIContext.setCredentialIssuerMetadata(credentialIssuer);

        List<OID4VCIContext.OID4VCCredential> availableCreds = getAvailableCredentials(credentialIssuer);
        log.infof("Available OID4VC credentials: %s", availableCreds);
        oid4VCIContext.setAvailableCredentials(availableCreds);

        try {
            return new InfoBean("OID4VCI well-known response", JsonSerialization.writeValueAsPrettyString(credentialIssuer));
        } catch (IOException ioe) {
            throw new MyException("Error when trying to deserialize OID4VCI well-known response to string", ioe);
        }
    }

    private InfoBean handleAuthzCodeFlow(ActionHandlerContext actionContext) {
        log.infof("handleAuthzCodeFlow");
        SessionData session = actionContext.getSession();

        OID4VCIContext oid4VCIContext = session.getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4VCIContext);

        if (oid4VCIContext.getCredentialIssuerMetadata() == null) {
            return new InfoBean("No credential issuer metadata", "Please first obtain OID4VCI credential issuer metadata from OID4VCI well-known endpoint");
        }

        if (oid4VCIContext.getSelectedCredentialId() == null && oid4VCIContext.getSelectedCredentialId().isBlank()) {
            return new InfoBean("No selected", "Please select OID4VCI credential to be used from available credentials");
        }

        CredentialIssuer credIssuerMetadata = oid4VCIContext.getCredentialIssuerMetadata();
        SupportedCredentialConfiguration supportedCredConfig = credIssuerMetadata.getCredentialsSupported().get(oid4VCIContext.getSelectedCredentialId());
        String scope = supportedCredConfig.getScope();

        String origLoginUrl = LoginUtil.getAuthorizationRequestUrl(session.getOidcConfigContext(), actionContext.getUriInfo(), scope);

        /// Add authorization_details to it
        List<OID4VCAuthorizationDetail> authzDetails = getAuthorizationDetailsForAuthzCodeFlow(credIssuerMetadata, oid4VCIContext.getSelectedCredentialId());
        try {
            String authzDetailsStr = JsonSerialization.writeValueAsString(authzDetails);

            String loginUrl = origLoginUrl + "&" + OAuth2Constants.AUTHORIZATION_DETAILS + "=" + URLEncoder.encode(authzDetailsStr, StandardCharsets.UTF_8);

            actionContext.getFmAttributes().put(Constants.AUTH_REQUEST_URL, loginUrl);
                return new InfoBean(
                        "Authorization details for OIDC authentication request", JsonSerialization.writeValueAsPrettyString(authzDetails),
                        "OIDC Authentication Request URL", loginUrl);
        } catch (IOException ioe) {
            throw new MyException("I/O exception when encode/decode authz details", ioe);
        }
    }

    private List<OID4VCAuthorizationDetail> getAuthorizationDetailsForAuthzCodeFlow(CredentialIssuer credIssuerMetadata, String selectedCredentialConfigId) {
        List<String> expectedMandatoryClaims = "education-certificate-config-id".equals(selectedCredentialConfigId) ? List.of("university", "education-certificate-number")
                : Collections.emptyList(); // TODO: Maybe update these to not be hardcoded this way...

        SupportedCredentialConfiguration supportedCredConfig = credIssuerMetadata.getCredentialsSupported().get(selectedCredentialConfigId);
        String format = supportedCredConfig.getFormat();

        List<ClaimsDescription> claimsDescriptions = expectedMandatoryClaims.stream()
                .map(expectedClaimName -> getMandatoryClaimForAuthzDetails(expectedClaimName, format))
                .toList();

        OID4VCAuthorizationDetail authDetail = new OID4VCAuthorizationDetail();
        authDetail.setType(OPENID_CREDENTIAL);
        authDetail.setCredentialConfigurationId(selectedCredentialConfigId);
        authDetail.setClaims(claimsDescriptions);
        authDetail.setLocations(Collections.singletonList(credIssuerMetadata.getCredentialIssuer()));

        return List.of(authDetail);
    }

    private ClaimsDescription getMandatoryClaimForAuthzDetails(String claimName, String format) {
        ClaimsDescription claim = new ClaimsDescription();

        // Construct claim path based on credential format
        List<Object> claimPath;
        if (OID4VCConstants.SD_JWT_VC_FORMAT.equals(format)) {
            claimPath = Arrays.asList(claimName);
        } else {
            claimPath = Arrays.asList("credentialSubject", claimName);
        }
        claim.setPath(claimPath);
        claim.setMandatory(true);
        return claim;
    }


    private InfoBean handleCreateCredentialOfferAction(ActionHandlerContext actionContext) {
        WebRequestContext<AbstractHttpPostRequest, AccessTokenResponse> lastTokenResponse = actionContext.getLastTokenResponse();
        SessionData session = actionContext.getSession();

        if (lastTokenResponse == null || lastTokenResponse.getResponse().getAccessToken() == null) {
            return new InfoBean("No Token Response", "No token response yet. Please login first.");
        } else {
            try {
                OID4VCIContext oid4VCIContext = session.getOrCreateOID4VCIContext();
                collectOID4VCIConfigParams(actionContext.getParams(), oid4VCIContext);

                if (oid4VCIContext.getCredentialIssuerMetadata() == null) {
                    return new InfoBean("No credential issuer metadata", "Please first obtain OID4VCI credential issuer metadata from OID4VCI well-known endpoint");
                }

                if (oid4VCIContext.getSelectedCredentialId() == null && oid4VCIContext.getSelectedCredentialId().isBlank()) {
                    return new InfoBean("No selected", "Please select OID4VCI credential to be used from available credentials");
                }

                // Step 1: Invoke credential-offer creation to Keycloak
                WebRequestContext<GenericRequestContext, CredentialOfferURI> credentialOfferCreation = invokeCredentialOfferCreation(oid4VCIContext, lastTokenResponse.getResponse(), oid4VCIContext.getSelectedCredentialId());
                oid4VCIContext.setCredentialOfferURI(credentialOfferCreation.getResponse());

                // Step 2: Invoke credential-offer URI
                CredentialOfferURI credentialOfferUri = oid4VCIContext.getCredentialOfferURI();
                String credOfferUriToInvoke = credentialOfferUri.getIssuer() + "/" + credentialOfferUri.getNonce();
                WebRequestContext<String, CredentialsOffer> credentialOffer = invokeCredentialOfferURI(credOfferUriToInvoke);
                oid4VCIContext.setCredentialsOffer(credentialOffer.getResponse());
                oid4VCIContext.setCredentialOfferURI(credentialOfferCreation.getResponse());

                // Step 3: Token-request with pre-authorized code
                WebRequestContext<GenericRequestContext, AccessTokenResponse> tokenResponse = triggerTokenRequestOfPreAuthorizationGrant(session.getAuthServerInfo().getTokenEndpoint(), credentialOffer.getResponse(), session);

                return new InfoBean(
                        "Request 1: Credential offer creation request", JsonSerialization.writeValueAsPrettyString(credentialOfferCreation.getRequest()),
                        "Response 1: Credential offer creation response", JsonSerialization.writeValueAsPrettyString(credentialOfferCreation.getResponse()),
                        "Request 2: Credential Offer request", credentialOffer.getRequest(),
                        "Response 2: Credential Offer response", JsonSerialization.writeValueAsPrettyString(credentialOffer.getResponse()),
                        "Request 3: Pre-authz grant Token request", JsonSerialization.writeValueAsPrettyString(tokenResponse.getRequest()),
                        "Response 3: Pre-authz grant Token response", JsonSerialization.writeValueAsPrettyString(tokenResponse.getResponse()));

            } catch (IOException ioe) {
                throw new MyException("Error when trying to deserialize response to string", ioe);
            }
        }
    }

    private InfoBean handlePreAuthzFlowWithOffer(ActionHandlerContext actionContext) {
        SessionData session = actionContext.getSession();
        OID4VCIContext oid4VCIContext = session.getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4VCIContext);

        String credentialOfferFullUri = oid4VCIContext.getPreauthzOffer();
        if (StringUtil.isBlank(credentialOfferFullUri)) {
            return new InfoBean("No credential offer", "Need to provide parameter: Credential offer (for pre-authorized grant with offer)");
        }
        log.infof("Using credential offer uri: %s", credentialOfferFullUri);

        String credentialOfferUri = getCredentialOfferUri(credentialOfferFullUri);
        if (StringUtil.isBlank(credentialOfferUri)) {
            return new InfoBean("No credential offer", "Was not able to parse credential offer from the provided Credential offer: " + credentialOfferFullUri);
        }
        log.infof("Calling uri '%s' to retrive credential offer", credentialOfferUri);

        try {
            // Step 1: Invoke credential-offer URI to obtain reference
            WebRequestContext<String, CredentialsOffer> credentialOffer = invokeCredentialOfferURI(credentialOfferUri);
            oid4VCIContext.setCredentialsOffer(credentialOffer.getResponse());

            // Step 2: Token-request with pre-authorized code
            WebRequestContext<GenericRequestContext, AccessTokenResponse> tokenResponse = triggerTokenRequestOfPreAuthorizationGrant(session.getAuthServerInfo().getTokenEndpoint(), credentialOffer.getResponse(), session);

            return new InfoBean(
                    "Request 1: Credential Offer request", credentialOffer.getRequest(),
                    "Response 1: Credential Offer response", JsonSerialization.writeValueAsPrettyString(credentialOffer.getResponse()),
                    "Request 2: Pre-authz grant Token request", JsonSerialization.writeValueAsPrettyString(tokenResponse.getRequest()),
                    "Response 2: Pre-authz grant Token response", JsonSerialization.writeValueAsPrettyString(tokenResponse.getResponse()));
        } catch (IOException ioe) {
            throw new MyException("Error when trying to deserialize response to string", ioe);
        }
    }

    private String getCredentialOfferUri(String fullOfferUri) {
        String[] splits = fullOfferUri.split("credential_offer_uri=");
        if (splits.length < 2) {
            return null;
        }
        String url = splits[1];
        return URLDecoder.decode(url, StandardCharsets.UTF_8);
    }

    // TODO: Use OAuthClient to invoke OID4VCI?
    private static CredentialIssuer invokeOID4VCIWellKnownEndpoint() {
        CloseableHttpClient httpClient = Services.instance().getHttpClient();
        String oid4vciWellKnownUrl = MyConstants.SERVER_ROOT + "/.well-known/openid-credential-issuer/realms/" + REALM_NAME;

        SimpleHttp simpleHttp = SimpleHttp.doGet(oid4vciWellKnownUrl, httpClient);
        try {
            return simpleHttp.asJson(CredentialIssuer.class);
        } catch (IOException ioe) {
            try {
                throw new MyException("Exception when triggered OID4VCI endpoint. Response was: " + simpleHttp.asString(), ioe);
            } catch (IOException ioe2) {
                throw new MyException("Exception when triggered OID4VCI endpoint. Original exception was: " + ioe.getMessage() + ", exception: " + ioe2.getMessage(), ioe2);
            }
        }
    }

    private void collectOID4VCIConfigParams(Map<String, String> params, OID4VCIContext oid4vciCtx) {
        String oid4vciCredential = params.get("oid4vci-credential");
        String claimsToPresent = params.get("oid4ci-claims-to-present");
        String preauthzClientId = params.get("oid4ci-preauthz-client_id");
        String preauthzUsername = params.get("oid4ci-preauthz-username");
        String preauthzOffer = params.get("oid4ci-preauthz-offer");
        log.infof("Selected oid4vciCredential: %s, claimsToPresent: %s, pre-authz clientId: %s, pre-authz username: %s, pre-authz offer: %s",
                oid4vciCredential, claimsToPresent, preauthzClientId, preauthzUsername, preauthzOffer);
        oid4vciCtx.setSelectedCredentialId(oid4vciCredential);
        oid4vciCtx.setClaimsToPresent(claimsToPresent);
        oid4vciCtx.setPreauthzClientId(preauthzClientId);
        oid4vciCtx.setPreauthzUsername(preauthzUsername);
        oid4vciCtx.setPreauthzOffer(preauthzOffer);
    }

    private List<OID4VCIContext.OID4VCCredential> getAvailableCredentials(CredentialIssuer credIssuer) {
        return credIssuer.getCredentialsSupported().entrySet()
                .stream()
                .map(this::getCredential)
                .collect(Collectors.toList());
    }

    private OID4VCIContext.OID4VCCredential getCredential(Map.Entry<String, SupportedCredentialConfiguration> credConfig) {
        OID4VCIContext.OID4VCCredential cred = new OID4VCIContext.OID4VCCredential();
        cred.setId(credConfig.getKey());
        cred.setDisplayName(credConfig.getKey());

        // Prefer english displayName from credential metadata if available
        CredentialMetadata credMetadata = credConfig.getValue().getCredentialMetadata();
        if (credMetadata != null && credMetadata.getDisplay() != null) {
            for (DisplayObject display : credMetadata.getDisplay()) {
                if ("en".equalsIgnoreCase(display.getLocale()) || "en-EN".equalsIgnoreCase(display.getLocale())) {
                    cred.setDisplayName(display.getName());
                }
            }
        }

        return cred;
    }


    private static WebRequestContext<GenericRequestContext, CredentialOfferURI> invokeCredentialOfferCreation(OID4VCIContext oid4vciCtx, AccessTokenResponse lastTokenResponse, String credentialConfigId) {
        CloseableHttpClient httpClient = Services.instance().getHttpClient();

        try {
            IDToken idToken = new JWSInput(lastTokenResponse.getIdToken()).readJsonContent(IDToken.class);
            String username = StringUtil.isNotBlank(oid4vciCtx.getPreauthzUsername()) ? oid4vciCtx.getPreauthzUsername() : idToken.getPreferredUsername();
            String clientId = StringUtil.isNotBlank(oid4vciCtx.getPreauthzClientId()) ? oid4vciCtx.getPreauthzClientId() : idToken.getIssuedFor();
            String credentialOfferCreationUri = getCredentialOfferUri(credentialConfigId, true, username, clientId);

            CredentialOfferURI credentialOfferURI;
            String credOfferURIStr = SimpleHttp.doGet(credentialOfferCreationUri, httpClient)
                    .auth(lastTokenResponse.getAccessToken())
                    .asString(); // TODO: OID4VCI This should not return JSON, but rather some generic URI instead. Should this be even invoked from this app?

            if (credOfferURIStr.contains("\"error\"")) {
                throw new MyException("Error when invoking credential creation endpoint: " + credOfferURIStr);
            }

            credentialOfferURI = JsonSerialization.readValue(credOfferURIStr, CredentialOfferURI.class);
            GenericRequestContext request = new GenericRequestContext(credentialOfferCreationUri, Map.of(HttpHeaders.AUTHORIZATION, "Bearer " + lastTokenResponse.getAccessToken()), (String) null);
            return new WebRequestContext<>(request, credentialOfferURI);
        } catch (JWSInputException | IOException ioe) {
            throw new MyException("Exception when triggered OID4VCI credential offer creation endpoint", ioe);
        }
    }

    private static WebRequestContext<String, CredentialsOffer> invokeCredentialOfferURI(String credOfferURI) {
        OAuthClient oauth = Services.instance().getOauthClient();
        CredentialOfferResponse credentialOfferResponse = oauth.oid4vc().credentialOfferRequest()
                .endpoint(credOfferURI)
                .send();
        return new WebRequestContext<>(credOfferURI, credentialOfferResponse.getCredentialsOffer());
    }

    private static String getCredentialOfferUri(String credentialConfigId, Boolean preAuthorized, String appUsername, String appClientId) {
        String res = Services.instance().getSession().getAuthServerInfo().getIssuer() + "/protocol/oid4vc/credential-offer-uri?credential_configuration_id=" + credentialConfigId;
        if (preAuthorized != null)
            res += "&pre_authorized=" + preAuthorized;
        if (appClientId != null)
            res += "&client_id=" + appClientId;
        if (appUsername != null)
            res += "&username=" + appUsername;
        return res;
    }

    private static WebRequestContext<GenericRequestContext, AccessTokenResponse> triggerTokenRequestOfPreAuthorizationGrant(String tokenEndpoint, CredentialsOffer credentialsOffer, SessionData session) {
        CloseableHttpClient httpClient = Services.instance().getHttpClient();
        PreAuthorizedCode preAuthorizedCode = credentialsOffer.getGrants().getPreAuthorizedCode();

        try {
            PreAuthorizedCodeGrantRequest preAuthzGrantRequest = Services.instance().getOauthClient().client(session.getRegisteredClient().getClientId())
                    .oid4vc()
                    .preAuthorizedCodeGrantRequest(preAuthorizedCode.getPreAuthorizedCode())
                    .endpoint(tokenEndpoint);
            AccessTokenResponse tokenResponse = preAuthzGrantRequest.send();

            List<OID4VCAuthorizationDetailResponse> authzDetails = tokenResponse.getAuthorizationDetails(OID4VCAuthorizationDetailResponse.class);
            if (authzDetails.size() != 1) {
                throw new MyException("Unexpected size of the authzDetails. Size was " + authzDetails.size() + ". The response was: " + JsonSerialization.writeValueAsString(tokenResponse));
            }

            OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
            oid4vciCtx.setAuthzDetails(authzDetails.get(0));

            // Save last access_token
            oid4vciCtx.setAccessToken(tokenResponse.getAccessToken());

            GenericRequestContext requestCtx = OAuthClientUtil.getRequestInfoAsCtx(preAuthzGrantRequest);

            return new WebRequestContext<>(requestCtx, tokenResponse);
        } catch (IOException ioe) {
            throw new MyException("Exception when triggered Token endpoint of pre-authorized grant", ioe);
        }
    }

    private static WebRequestContext<GenericRequestContext, Object> triggerCredentialRequest(OID4VCIContext oid4VCIContext) {
        CloseableHttpClient httpClient = Services.instance().getHttpClient();
        try {
            CredentialRequest credentialRequest = new CredentialRequest();
            credentialRequest.setCredentialIdentifier(oid4VCIContext.getAuthzDetails().getCredentialIdentifiers().get(0));

            String accessToken = oid4VCIContext.getAccessToken();

            String credentialEndpoint = oid4VCIContext.getCredentialIssuerMetadata().getCredentialEndpoint();
            String credResponse = SimpleHttp.doPost(credentialEndpoint, httpClient)
                    .auth(accessToken)
                    .header(HttpHeaders.CONTENT_TYPE, "application/json")
                    .json(credentialRequest)
                    .asString();

            Map<String, String> headers = Map.of(HttpHeaders.CONTENT_TYPE, "application/json",
                    "Authorization", "Bearer " + accessToken);
            GenericRequestContext ctx = new GenericRequestContext(credentialEndpoint, headers, JsonSerialization.writeValueAsPrettyString(credentialRequest));

            CredentialResponse credentialResponse;
            try {
                credentialResponse = JsonSerialization.readValue(credResponse, CredentialResponse.class);
                return new WebRequestContext<>(ctx, credentialResponse);
            } catch (IOException ioe) {
                // This happens in case of error
                return new WebRequestContext<>(ctx, credResponse);
            }
        } catch (IOException e) {
            throw new MyException("Failed to invoke credential request or parse credential response", e);
        }
    }

    private InfoBean credentialRequest(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        String oid4vcAccessToken = oid4vciCtx.getAccessToken();

        if (oid4vcAccessToken == null) {
            return new InfoBean("No OID4VCI access token", "No access token capable of doing OID4VCI credential request. Please start OID4VCI authorization-code or pre-authorization code grant");
        }

        try {
            WebRequestContext<GenericRequestContext, Object> credentialResponse = triggerCredentialRequest(oid4vciCtx);
            if (credentialResponse.getResponse() instanceof CredentialResponse) {
                oid4vciCtx.setCredentialResponse((CredentialResponse) credentialResponse.getResponse());

                return new InfoBean(
                        "Credential request", JsonSerialization.writeValueAsPrettyString(credentialResponse.getRequest()),
                        "Credential response", JsonSerialization.writeValueAsPrettyString(credentialResponse.getResponse()));
            } else {
                return new InfoBean(
                        "Credential request", JsonSerialization.writeValueAsPrettyString(credentialResponse.getRequest()),
                        "Credential response - error", JsonSerialization.writeValueAsPrettyString(credentialResponse.getResponse()));
            }
        } catch (IOException ioe) {
            throw new MyException("Unexpected exception when preparing/sending credential request");
        }
    }

    private InfoBean getLastCredentialResponse(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        if (oid4vciCtx.getCredentialResponse() == null) {
            return new InfoBean("No verifiable credential", "No OID4VCI verifiable credential present. Please first start credential issuance flow.");
        } else {
            CredentialResponse credentialResponse = oid4vciCtx.getCredentialResponse();
            String credentialStr = credentialResponse.getCredentials().get(0).getCredential().toString();

            try {
                // Assumptions it is Sd-JWT VC. TODO: Make it working for W3C credentials...
                SdJwtVP sdJWTVP = SdJwtVP.of(credentialStr);
                JWSHeader jwsHeader = sdJWTVP.getIssuerSignedJWT().getJwsHeader();
                JsonNode payloadNode = sdJWTVP.getIssuerSignedJWT().getPayload();

                StringBuilder claimsStr = new StringBuilder("{");
                for (Map.Entry<String, ArrayNode> claim : sdJWTVP.getClaims().entrySet()) {
                    claimsStr.append(" " + claim.getKey() + " = " + JsonSerialization.writeValueAsPrettyString(claim.getValue()) + "\n");
                }
                claimsStr.append("}");

                return new InfoBean(
                        "Plain-credential", credentialStr,
                        "Sd-JWT credential - header", JsonSerialization.writeValueAsPrettyString(jwsHeader),
                        "Sd-JWT credential - payload", JsonSerialization.writeValueAsPrettyString(payloadNode),
                        "Sd-JWT disclosed claims", claimsStr.toString());
            } catch (IOException ioe) {
                throw new MyException("Exception when displaying latest verifiable credential", ioe);
            }
        }
    }

    private InfoBean createPresentation(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4vciCtx);

        if (oid4vciCtx.getCredentialResponse() == null) {
            return new InfoBean("No verifiable credential", "No OID4VCI verifiable credential present. Please first start credential issuance flow.");
        } else {
            CredentialResponse credentialResponse = oid4vciCtx.getCredentialResponse();
            String credentialStr = credentialResponse.getCredentials().get(0).getCredential().toString();

            List<String> claimsToPresent = oid4vciCtx.getClaimsToPresent() == null ? Collections.emptyList() : List.of(oid4vciCtx.getClaimsToPresent().split(","));

            try {
                // Assumptions it is Sd-JWT VC. TODO: Make it working for W3C credentials...
                SdJwtVP sdJWTVP = SdJwtVP.of(credentialStr);

                String newSdJWT = sdJWTVP.presentWithSpecifiedClaims (claimsToPresent, false, null, null);
                log.infof("New sd JWT: %s",  newSdJWT);

                SdJwtVP presentation = SdJwtVP.of(newSdJWT);

                JWSHeader jwsHeader = presentation.getIssuerSignedJWT().getJwsHeader();
                JsonNode payloadNode = presentation.getIssuerSignedJWT().getPayload();

                StringBuilder claimsStr = new StringBuilder("{");
                for (Map.Entry<String, ArrayNode> claim : presentation.getClaims().entrySet()) {
                    claimsStr.append(" " + claim.getKey() + " = " + JsonSerialization.writeValueAsPrettyString(claim.getValue()) + "\n");
                }
                claimsStr.append("}");

                return new InfoBean(
                        "Plain-presentation", credentialStr,
                        "Sd-JWT presentation - header", JsonSerialization.writeValueAsPrettyString(jwsHeader),
                        "Sd-JWT presentation - payload", JsonSerialization.writeValueAsPrettyString(payloadNode),
                        "Sd-JWT presentation - disclosed claims", claimsStr.toString());
            } catch (IOException ioe) {
                throw new MyException("Exception when displaying latest presentation", ioe);
            }
        }

    }

    private InfoBean createRequiredAction(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4vciCtx);
        String username = StringUtil.isNotBlank(oid4vciCtx.getPreauthzUsername()) ? oid4vciCtx.getPreauthzUsername() : null;
        if (username == null) {
            return new InfoBean("No username provided", "Fill username field to find the user to whom required action would be created");
        }
        try (Keycloak adminClient = Services.instance().getAdminClient()) {
            List<UserRepresentation> users = adminClient.realm(REALM_NAME).users().search(username);
            if (users.isEmpty()) {
                return new InfoBean("User not found", "User " + username + " not found");
            } else if (users.size() > 1) {
                return new InfoBean("More users found", "More users for " + username + ". Please adjust searching.");
            } else {
                // Set required-action to the user
                UserRepresentation userRep = users.get(0);
                UserResource user = adminClient.realm(REALM_NAME).users().get(userRep.getId());

                if (oid4vciCtx.getSelectedCredentialId() == null && oid4vciCtx.getSelectedCredentialId().isBlank()) {
                    return new InfoBean("No selected", "Please select OID4VCI credential to be used from available credentials");
                }
                CredentialIssuer credIssuerMetadata = oid4vciCtx.getCredentialIssuerMetadata();
                SupportedCredentialConfiguration supportedCredConfig = credIssuerMetadata.getCredentialsSupported().get(oid4vciCtx.getSelectedCredentialId());
                String clientScopeName = supportedCredConfig.getScope();

                VerifiableCredentialOfferAction.CredentialOfferUserConfig cfg = new VerifiableCredentialOfferAction.CredentialOfferUserConfig();
                cfg.setClientScopeName(clientScopeName);
                String reqAction = VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID + ":" + cfg.asConfigString();
                userRep.setRequiredActions(List.of(VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID + ":" + cfg.asConfigString()));
                user.update(userRep);

                try {
                    Map<String, String> result = Map.of("username", username, "Required action", reqAction, "Client scope", clientScopeName);
                    return new InfoBean("User updated", JsonSerialization.writeValueAsPrettyString(result));
                } catch (IOException ioe) {
                    throw new MyException("Error when providing user");
                }
            }
        }
    }

}
