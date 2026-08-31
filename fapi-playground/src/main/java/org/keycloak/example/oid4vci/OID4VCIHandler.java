package org.keycloak.example.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.VCFormat;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.example.Services;
import org.keycloak.example.bean.InfoBean;
import org.keycloak.example.handlers.ActionHandler;
import org.keycloak.example.handlers.ActionHandlerContext;
import org.keycloak.example.util.*;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsParser;
import org.keycloak.protocol.oid4vc.model.*;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.testsuite.util.oauth.AbstractHttpPostRequest;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.LoginUrlBuilder;
import org.keycloak.testsuite.util.oauth.oid4vc.*;
import org.keycloak.util.AuthorizationDetailsParser;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.keycloak.constants.OID4VCIConstants.VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID;
import static org.keycloak.example.util.MyConstants.REALM_NAME;

public class OID4VCIHandler implements ActionHandler {

    private static final Logger log = Logger.getLogger(OID4VCIHandler.class);

    static {
        AuthorizationDetailsParser.registerParser(OPENID_CREDENTIAL, new OID4VCAuthorizationDetailsParser());
    }

    @Override
    public Map<String, Function<ActionHandlerContext, InfoBean>> getActions() {
        return Map.of(
                "oid4vci-wellknown-endpoint", this::handleOID4VCIWellKnownEndpointAction,
                "oid4vci-authz-code-flow", this::handleAuthzCodeFlow,
                "oid4vci-pre-authz-code-flow", this::handleCreateCredentialOfferAction,
                "oid4vci-aia", this::handleAIAFlow,
                "oid4vci-pre-authz-code-with-offer", this::handlePreAuthzFlowWithOffer,
                "oid4vci-credential-request", this::credentialRequest,
                "oid4vci-last-credential-response", this::getLastCredentialResponse,
                "oid4vci-create-presentation", this::createPresentation,
                "oid4vci-generate-attestation-key", this::generateAttestationKey
        );
    }

    @Override
    public void onAuthenticationCallback(SessionData session, AccessTokenResponse accessTokenResponse) {
        if (accessTokenResponse.getAuthorizationDetails() == null || accessTokenResponse.getAuthorizationDetails().isEmpty()) {
            return;
        }
        List<OID4VCAuthorizationDetail> authzDetails = accessTokenResponse.getAuthorizationDetails()
                .stream()
                .map(authDetail -> authDetail.asSubtype(OID4VCAuthorizationDetail.class))
                .toList();

        if (authzDetails.isEmpty()) {
            return;
        } else if (authzDetails.size() > 1) {
            throw new MyException("Unexpected size of the authzDetails. Size was " + authzDetails.size() + ". The response had authorization details: " + accessTokenResponse.getAuthorizationDetails());
        }
        OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
        oid4vciCtx.setAuthzDetails(authzDetails.get(0));
    }

    @Override
    public void onLogoutCallback(SessionData session) {
        OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
        oid4vciCtx.cleanup();
    }

    private InfoBean handleOID4VCIWellKnownEndpointAction(ActionHandlerContext actionContext) {
        try {
            WebRequestContext<CredentialIssuerMetadataRequest, CredentialIssuerMetadataResponse> ctx = invokeOID4VCIWellKnownEndpoint();
            CredentialIssuer credentialIssuer = ctx.getResponse().getMetadata();

            OID4VCIContext oid4VCIContext = actionContext.getSession().getOrCreateOID4VCIContext();
            oid4VCIContext.setCredentialIssuerMetadata(credentialIssuer);

            List<OID4VCIContext.OID4VCCredential> availableCreds = getAvailableCredentials(credentialIssuer);
            log.infof("Available OID4VC credentials: %s", availableCreds);
            oid4VCIContext.setAvailableCredentials(availableCreds);

            return new InfoBean(
                    "OID4VCI well-known request", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(ctx.getRequest())),
                    "OID4VCI well-known response", JsonSerialization.writeValueAsPrettyString(credentialIssuer));
        } catch (IOException ioe) {
            throw new MyException("Error when trying to deserialize OID4VCI well-known response to string", ioe);
        }
    }

    private InfoBean handleAuthzCodeFlow(ActionHandlerContext actionContext) {
        SessionData session = actionContext.getSession();

        OID4VCIContext oid4VCIContext = session.getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4VCIContext);

        String configuredCredentialOfferURI = oid4VCIContext.getConfiguredCredentialOffer();
        log.infof("handle authorization code flow. Credential offer from the config: %s", configuredCredentialOfferURI);

        if (oid4VCIContext.getCredentialIssuerMetadata() == null) {
            return new InfoBean("No credential issuer metadata", "Please first obtain OID4VCI credential issuer metadata from OID4VCI well-known endpoint");
        }

        if (oid4VCIContext.getSelectedCredentialId() == null && oid4VCIContext.getSelectedCredentialId().isBlank()) {
            return new InfoBean("No selected", "Please select OID4VCI credential to be used from available credentials");
        }

        CredentialIssuer credIssuerMetadata = oid4VCIContext.getCredentialIssuerMetadata();
        SupportedCredentialConfiguration supportedCredConfig = credIssuerMetadata.getCredentialsSupported().get(oid4VCIContext.getSelectedCredentialId());
        String scope = supportedCredConfig.getScope();

        InfoBean info = new InfoBean();

        try {
            LoginUrlBuilder loginUrlBuilder = LoginUtil.getAuthorizationRequestUrl(session.getOidcConfigContext(), actionContext.getUriInfo(), scope);

            // The field "Credential offer" was configured
            if (StringUtil.isNotBlank(configuredCredentialOfferURI)) {
                CredentialOfferURI credentialOfferUri = getCredentialOfferUri(configuredCredentialOfferURI);
                if (credentialOfferUri == null) {
                    return new InfoBean("No credential offer", "Was not able to parse credential offer from the provided Credential offer: " + configuredCredentialOfferURI);
                }
                log.infof("Calling uri '%s' to retrive credential offer", credentialOfferUri.getCredentialOfferUri());

                WebRequestContext<CredentialOfferRequest, CredentialOfferResponse> credentialOffer = invokeCredentialOfferURI(credentialOfferUri);
                oid4VCIContext.setCredentialsOffer(credentialOffer.getResponse().getCredentialsOffer());

                String issuerState = credentialOffer.getResponse().getCredentialsOffer().getIssuerState();
                loginUrlBuilder.issuerState(issuerState);

                info.addOutput("Credential Offer request", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(credentialOffer.getRequest())));
                info.addOutput("Credential Offer response", JsonSerialization.writeValueAsPrettyString(credentialOffer.getResponse()));
            }

            String origLoginUrl = loginUrlBuilder.build();

            /// Add authorization_details to it
            List<OID4VCAuthorizationDetail> authzDetails = getAuthorizationDetailsForAuthzCodeFlow(credIssuerMetadata, oid4VCIContext.getSelectedCredentialId());

            String authzDetailsStr = JsonSerialization.writeValueAsString(authzDetails);

            String loginUrl = origLoginUrl + "&" + OAuth2Constants.AUTHORIZATION_DETAILS + "=" + URLEncoder.encode(authzDetailsStr, StandardCharsets.UTF_8);

            actionContext.getFmAttributes().put(Constants.AUTH_REQUEST_URL, loginUrl);

            info.addOutput("Authorization details for OIDC authentication request", JsonSerialization.writeValueAsPrettyString(authzDetails));
            info.addOutput("OIDC Authentication Request URL", loginUrl);
            return info;
        } catch (IOException ioe) {
            throw new MyException("I/O exception when encode/decode authz details", ioe);
        }
    }

    private List<OID4VCAuthorizationDetail> getAuthorizationDetailsForAuthzCodeFlow(CredentialIssuer credIssuerMetadata, String selectedCredentialConfigId) {
        List<String> expectedMandatoryClaims = "education-certificate-config-id".equals(selectedCredentialConfigId) || "education-certificate".equals(selectedCredentialConfigId) ? List.of("university", "education-certificate-number")
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
        if (VCFormat.SD_JWT_VC.equals(format)) {
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
                WebRequestContext<CredentialOfferUriRequest, CredentialOfferUriResponse> credentialOfferCreation = invokeCredentialOfferCreation(oid4VCIContext, lastTokenResponse.getResponse(), oid4VCIContext.getSelectedCredentialId());
                oid4VCIContext.setCredentialOfferURI(credentialOfferCreation.getResponse().getCredentialOfferURI());

                // Step 2: Invoke credential-offer URI
                CredentialOfferURI credentialOfferUri = oid4VCIContext.getCredentialOfferURI();
                WebRequestContext<CredentialOfferRequest, CredentialOfferResponse> credentialOffer = invokeCredentialOfferURI(credentialOfferUri);
                oid4VCIContext.setCredentialsOffer(credentialOffer.getResponse().getCredentialsOffer());

                // Step 3: Token-request with pre-authorized code
                WebRequestContext<PreAuthorizedCodeGrantRequest, AccessTokenResponse> tokenResponse = triggerTokenRequestOfPreAuthorizationGrant(session.getAuthServerInfo().getTokenEndpoint(), credentialOffer.getResponse().getCredentialsOffer(), session);

                return new InfoBean(
                        "Request 1: Credential offer creation request (admin)", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(credentialOfferCreation.getRequest())),
                        "Response 1: Credential offer creation response (admin)", JsonSerialization.writeValueAsPrettyString(credentialOfferCreation.getResponse()),
                        "Request 2: Credential Offer request (user)", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(credentialOffer.getRequest())),
                        "Response 2: Credential Offer response (user)", JsonSerialization.writeValueAsPrettyString(credentialOffer.getResponse()),
                        "Request 3: Pre-authz grant Token request (user)", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(tokenResponse.getRequest())),
                        "Response 3: Pre-authz grant Token response (user)", JsonSerialization.writeValueAsPrettyString(tokenResponse.getResponse()));

            } catch (IOException ioe) {
                throw new MyException("Error when trying to deserialize response to string", ioe);
            }
        }
    }

    private InfoBean handlePreAuthzFlowWithOffer(ActionHandlerContext actionContext) {
        SessionData session = actionContext.getSession();
        OID4VCIContext oid4VCIContext = session.getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4VCIContext);

        String credentialOfferFullUri = oid4VCIContext.getConfiguredCredentialOffer();
        if (StringUtil.isBlank(credentialOfferFullUri)) {
            return new InfoBean("No credential offer", "Need to provide parameter: Credential offer (for pre-authorized grant with offer)");
        }
        log.infof("Using credential offer uri: %s", credentialOfferFullUri);

        CredentialOfferURI credentialOfferUri = getCredentialOfferUri(credentialOfferFullUri);
        if (credentialOfferUri == null) {
            return new InfoBean("No credential offer", "Was not able to parse credential offer from the provided Credential offer: " + credentialOfferFullUri);
        }
        log.infof("Calling uri '%s' to retrive credential offer", credentialOfferUri.getCredentialOfferUri());

        try {
            // Step 1: Invoke credential-offer URI to obtain reference
            WebRequestContext<CredentialOfferRequest, CredentialOfferResponse> credentialOffer = invokeCredentialOfferURI(credentialOfferUri);
            oid4VCIContext.setCredentialsOffer(credentialOffer.getResponse().getCredentialsOffer());

            // Step 2: Token-request with pre-authorized code
            WebRequestContext<PreAuthorizedCodeGrantRequest, AccessTokenResponse> tokenResponse = triggerTokenRequestOfPreAuthorizationGrant(session.getAuthServerInfo().getTokenEndpoint(),
                    credentialOffer.getResponse().getCredentialsOffer(), session);

            return new InfoBean(
                    "Request 1: Credential Offer request", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(credentialOffer.getRequest())),
                    "Response 1: Credential Offer response", JsonSerialization.writeValueAsPrettyString(credentialOffer.getResponse()),
                    "Request 2: Pre-authz grant Token request", JsonSerialization.writeValueAsPrettyString(OAuthClientUtil.getRequestInfo(tokenResponse.getRequest())),
                    "Response 2: Pre-authz grant Token response", JsonSerialization.writeValueAsPrettyString(tokenResponse.getResponse()));
        } catch (IOException ioe) {
            throw new MyException("Error when trying to deserialize response to string", ioe);
        }
    }

    private CredentialOfferURI getCredentialOfferUri(String fullOfferUri) {
        String[] splits = fullOfferUri.split("credential_offer_uri=");
        if (splits.length < 2) {
            return null;
        }
        String url = splits[1];
        String url1 = URLDecoder.decode(url, StandardCharsets.UTF_8);

        int lastIndex = url1.lastIndexOf('/');
        CredentialOfferURI credOfferURI = new CredentialOfferURI();
        credOfferURI.setIssuer(url1.substring(0, lastIndex));
        credOfferURI.setNonce(url1.substring(lastIndex));
        return credOfferURI;
    }


    private static WebRequestContext<CredentialIssuerMetadataRequest, CredentialIssuerMetadataResponse> invokeOID4VCIWellKnownEndpoint() {
        OAuthClient oauth = Services.instance().getOauthClient();
        String oid4vciWellKnownUrl = MyConstants.SERVER_ROOT + "/.well-known/openid-credential-issuer/realms/" + REALM_NAME;

        CredentialIssuerMetadataRequest request = oauth.oid4vc().issuerMetadataRequest()
                .endpoint(oid4vciWellKnownUrl);
        CredentialIssuerMetadataResponse response = request.send();
        return new WebRequestContext<>(request, response);
    }

    private void collectOID4VCIConfigParams(Map<String, String> params, OID4VCIContext oid4vciCtx) {
        String oid4vciCredential = params.get("oid4vci-credential");
        boolean preAuthorized = params.get("oid4vci-pre-authorized") != null;
        String claimsToPresent = params.get("oid4ci-claims-to-present");
        String preauthzClientId = params.get("oid4ci-preauthz-client_id");
        String preauthzUsername = params.get("oid4ci-preauthz-username");
        String preauthzOffer = params.get("oid4ci-preauthz-offer");
        String proofType = params.getOrDefault("oid4vci-proof-type", "none");
        boolean useAttestationForJwtProof = params.get("oid4vci-jwt-use-attestation") != null;
        log.infof("Selected oid4vciCredential: %s, preAuthorized: %s, claimsToPresent: %s, pre-authz clientId: %s, pre-authz username: %s, pre-authz offer: %s, proofType: %s, useAttestationForJwtProof: %s",
                oid4vciCredential, preAuthorized, claimsToPresent, preauthzClientId, preauthzUsername, preauthzOffer, proofType, useAttestationForJwtProof);
        oid4vciCtx.setSelectedCredentialId(oid4vciCredential);
        oid4vciCtx.setPreAuthorized(preAuthorized);
        oid4vciCtx.setClaimsToPresent(claimsToPresent);
        oid4vciCtx.setPreauthzClientId(preauthzClientId);
        oid4vciCtx.setPreauthzUsername(preauthzUsername);
        oid4vciCtx.setConfiguredCredentialOffer(preauthzOffer);
        oid4vciCtx.setProofType(proofType);
        oid4vciCtx.setUseAttestationForJwtProof(useAttestationForJwtProof);
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


    private static WebRequestContext<CredentialOfferUriRequest, CredentialOfferUriResponse> invokeCredentialOfferCreation(OID4VCIContext oid4vciCtx, AccessTokenResponse lastTokenResponse, String credentialConfigId) {
        OAuthClient oauth = Services.instance().getOauthClient();

        try {
            IDToken idToken = new JWSInput(lastTokenResponse.getIdToken()).readJsonContent(IDToken.class);
            String username = StringUtil.isNotBlank(oid4vciCtx.getPreauthzUsername()) ? oid4vciCtx.getPreauthzUsername() : idToken.getPreferredUsername();
            String clientId = StringUtil.isNotBlank(oid4vciCtx.getPreauthzClientId()) ? oid4vciCtx.getPreauthzClientId() : idToken.getIssuedFor();

            CredentialOfferUriRequest credRequest = oauth.oid4vc()
                    .credentialOfferUriRequest(credentialConfigId)
                    .preAuthorized(true) // TODO: should not be hardcoded to pre-authorized. Add support for "authorization-code" flow
                    .bearerToken(lastTokenResponse.getAccessToken())
                    .targetUser(username);

            CredentialOfferUriResponse  credentialOfferURIResponse = credRequest.send();

            if (credentialOfferURIResponse.getError() != null) {
                throw new MyException("Error when invoking credential creation endpoint. Error: " + credentialOfferURIResponse.getError() +
                        ", Error description: " + credentialOfferURIResponse.getErrorDescription());
            }

            return new WebRequestContext<>(credRequest, credentialOfferURIResponse);
        } catch (JWSInputException ioe) {
            throw new MyException("Exception when triggered OID4VCI credential offer creation endpoint", ioe);
        }
    }

    private static WebRequestContext<CredentialOfferRequest, CredentialOfferResponse> invokeCredentialOfferURI(CredentialOfferURI credOfferURI) {
        OAuthClient oauth = Services.instance().getOauthClient();
        CredentialOfferRequest credentialOfferRequest = oauth.oid4vc().credentialOfferRequest(credOfferURI);
        CredentialOfferResponse credentialOfferResponse =credentialOfferRequest.send();
        return new WebRequestContext<>(credentialOfferRequest, credentialOfferResponse);
    }

    private static WebRequestContext<PreAuthorizedCodeGrantRequest, AccessTokenResponse> triggerTokenRequestOfPreAuthorizationGrant(String tokenEndpoint, CredentialsOffer credentialsOffer, SessionData session) {
        String preAuthorizedCode = credentialsOffer.getPreAuthorizedCode();

        try {
            PreAuthorizedCodeGrantRequest preAuthzGrantRequest = Services.instance().getOauthClient().client(session.getRegisteredClient().getClientId())
                    .oid4vc()
                    .preAuthorizedCodeGrantRequest(preAuthorizedCode)
                    .endpoint(tokenEndpoint);
            AccessTokenResponse tokenResponse = preAuthzGrantRequest.send();

            List<OID4VCAuthorizationDetail> authzDetails = tokenResponse.getOID4VCAuthorizationDetails();
            if (authzDetails.size() != 1) {
                throw new MyException("Unexpected size of the authzDetails. Size was " + authzDetails.size() + ". The response was: " + JsonSerialization.writeValueAsString(tokenResponse));
            }

            OID4VCIContext oid4vciCtx = session.getOrCreateOID4VCIContext();
            oid4vciCtx.setAuthzDetails(authzDetails.get(0));

            // Save last access_token TODO: Should be done differently as accessToken is saved in the OIDC context
            // oid4vciCtx.setAccessToken(tokenResponse.getAccessToken());

            return new WebRequestContext<>(preAuthzGrantRequest, tokenResponse);
        } catch (IOException ioe) {
            throw new MyException("Exception when triggered Token endpoint of pre-authorized grant", ioe);
        }
    }

    /**
     * Carries data related to credential request and response (including used proofs, nonces etc)
     */
    private static class CredentialRequestFullContext {

        WebRequestContext<Oid4vcCredentialRequest, MyOid4vcCredentialResponse> credentialRequestCtx;
        Map<String, Object> nonceRequest;
        String nonceResponse;
        String proofType;
        String proofJwt;

        public void setCredentialRequestContext(WebRequestContext<Oid4vcCredentialRequest, MyOid4vcCredentialResponse> credentialRequestCtx) {
            this.credentialRequestCtx = credentialRequestCtx;
        }

        public void setProofContext(Map<String, Object> nonceRequest, String nonceResponse, String proofType, String proofJwt) {
            this.nonceRequest = nonceRequest;
            this.nonceResponse = nonceResponse;
            this.proofType = proofType;
            this.proofJwt = proofJwt;
        }

    };


    private static CredentialRequestFullContext triggerCredentialRequest(
            OID4VCIContext oid4VCIContext, String accessToken) {
        OAuthClient oauth = Services.instance().getOauthClient();
        try {
            Oid4vcCredentialRequest credentialRequest = oauth.oid4vc().credentialRequest()
                    .credentialIdentifier(oid4VCIContext.getAuthzDetails().getCredentialIdentifiers().get(0))
                    .bearerToken(accessToken);

            CredentialRequestFullContext result = new CredentialRequestFullContext();

            String proofType = oid4VCIContext.getProofType();
            if (proofType != null && !"none".equals(proofType)) {
                Oid4vcNonceRequest nonceReq = oauth.oid4vc().nonceRequest();
                Oid4vcNonceResponse nonceResp = nonceReq.send();
                String cNonce = nonceResp.getNonce();

                String credentialIssuer = oauth.oid4vc().issuerMetadataRequest().send().getMetadata().getCredentialIssuer();
                Proofs proofs = ProofUtil.buildProofs(proofType, credentialIssuer, cNonce, oid4VCIContext.getAttestationKey(), oid4VCIContext.isUseAttestationForJwtProof());
                credentialRequest.proofs(proofs);
                log.infof("Attaching '%s' proof to credential request (c_nonce obtained from nonce endpoint, useAttestationForJwtProof: %s)", proofType, oid4VCIContext.isUseAttestationForJwtProof());

                String proofJwt = extractProofJwt(proofType, proofs);
                result.setProofContext(
                        OAuthClientUtil.getRequestInfo(nonceReq),
                        JsonSerialization.writeValueAsPrettyString(nonceResp.getNonceResponse()),
                        proofType,
                        proofJwt
                );
            }

            Oid4vcCredentialResponse credentialResponse = credentialRequest.send();
            MyOid4vcCredentialResponse credResponse = new MyOid4vcCredentialResponse(credentialResponse);
            WebRequestContext<Oid4vcCredentialRequest, MyOid4vcCredentialResponse> credentialRequestCtx =  new WebRequestContext<>(credentialRequest, credResponse);
            result.setCredentialRequestContext(credentialRequestCtx);
            return result;
        } catch (Exception e) {
            throw new MyException("Failed to invoke credential request or parse credential response. Details: " + e.getMessage(), e);
        }
    }

    /**
     * Extract the raw JWT string from the {@link Proofs} based on proof type.
     */
    private static String extractProofJwt(String proofType, Proofs proofs) {
        if (ProofType.JWT.equals(proofType) && proofs.getJwt() != null && !proofs.getJwt().isEmpty()) {
            return proofs.getJwt().get(0);
        } else if (ProofType.ATTESTATION.equals(proofType) && proofs.getAttestation() != null && !proofs.getAttestation().isEmpty()) {
            return proofs.getAttestation().get(0);
        }
        return null;
    }

    /**
     * Parse a JWT string and return a pretty-printed JSON of its decoded header.
     */
    private static String parseJwtHeader(String jwt) {
        try {
            JWSInput jwsInput = new JWSInput(jwt);
            JWSHeader jwsHeader = jwsInput.getHeader();
            return JsonSerialization.writeValueAsPrettyString(jwsHeader);
        } catch (Exception e) {
            return jwt; // fall back to raw if unparseable
        }
    }

    /**
     * Parse a JWT string and return a pretty-printed JSON of its decoded payload.
     */
    private static String parseJwtPayload(String jwt) {
        try {
            JWSInput jwsInput = new JWSInput(jwt);
            JsonNode node = jwsInput.readJsonContent(JsonNode.class);
            return JsonSerialization.writeValueAsPrettyString(node);
        } catch (Exception e) {
            return jwt; // fall back to raw if unparseable
        }
    }

    private InfoBean generateAttestationKey(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        KeyWrapper newKey = ProofUtil.createEcKeyPair(true);
        oid4vciCtx.setAttestationKey(newKey);
        PersistenceProvider.saveAttestationKey(oid4vciCtx);

        try {
            JWK publicJwk = JWKBuilder.create().ec(newKey.getPublicKey());
            publicJwk.setKeyId(newKey.getKid());
            publicJwk.setAlgorithm(newKey.getAlgorithm());

            // Wrap single JWK in a JWKS structure {"keys": [...]} for display
            Map<String, Object> jwksMap = Map.of("keys", List.of(publicJwk));
            String jwksStr = JsonSerialization.writeValueAsPrettyString(jwksMap);
            return new InfoBean(
                    "Attestation key generated",
                    "A new EC (ES256) attestation key has been generated. Configure a 'Trusted Key' identity provider " +
                    "in Keycloak with the JWKS shown below, and make sure your client references that IDP.",
                    "Attestation key (public JWKS)",
                    jwksStr);
        } catch (IOException e) {
            throw new MyException("Failed to serialize attestation key to JWKS", e);
        }
    }

    private InfoBean credentialRequest(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();

        // Fix: apply form params (including proof type) before processing the request
        collectOID4VCIConfigParams(actionContext.getParams(), oid4vciCtx);

        String oid4vcAccessToken = actionContext.getSession().getTokenRequestCtx().getResponse().getAccessToken();

        if (oid4vcAccessToken == null) {
            return new InfoBean("No OID4VCI access token", "No access token capable of doing OID4VCI credential request. Please start OID4VCI authorization-code or pre-authorization code grant");
        }

        if (!checkAttestationKeyPresentIfNeeded(oid4vciCtx)) {
            return new InfoBean("Attestation key missing",
                    "Please generate and configure attestation key by clicking 'Generate attestation key' first, " +
                    "then configure the corresponding Trusted Key identity provider in Keycloak.");
        }

        try {
            CredentialRequestFullContext fullContext =
                    triggerCredentialRequest(oid4vciCtx, oid4vcAccessToken);

            WebRequestContext<Oid4vcCredentialRequest, MyOid4vcCredentialResponse> credentialResponse = fullContext.credentialRequestCtx;
            Map<String, Object> credRequest = OAuthClientUtil.getRequestInfo(credentialResponse.getRequest());
            credRequest.put("Body", credentialResponse.getRequest().getCredentialRequest());

            String credentialResponseStr;
            try {
                oid4vciCtx.setCredentialResponse(credentialResponse.getResponse().getCredentialResponse());
                credentialResponseStr = JsonSerialization.writeValueAsPrettyString(credentialResponse.getResponse());
            } catch (IllegalStateException iae) {
                credentialResponseStr = "IllegalStateException: " + iae.getMessage();
            }

            InfoBean info = new InfoBean();

            // Add "nonce" if it was used
            if (fullContext.nonceRequest != null) {
                info.addOutput("Nonce request", JsonSerialization.writeValueAsPrettyString(fullContext.nonceRequest));
                info.addOutput("Nonce response", fullContext.nonceResponse);
            }

            info.addOutput("Credential request", JsonSerialization.writeValueAsPrettyString(credRequest));

            // Append proof-related display entries when a proof was used
            if (ProofType.JWT.equals(fullContext.proofType) && fullContext.proofJwt != null) {
                info.addOutput("JWT proof (parsed header)", parseJwtHeader(fullContext.proofJwt));
                info.addOutput("JWT proof (parsed payload)", parseJwtPayload(fullContext.proofJwt));

                JWSHeader jwsHeader = new JWSInput(fullContext.proofJwt).getHeader();
                String keyAttestationJwt = (String) jwsHeader.getOtherClaims().get("key_attestation");
                if (keyAttestationJwt != null) {
                    info.addOutput("Key attestation JWT (parsed header)", parseJwtHeader(keyAttestationJwt));
                    info.addOutput("Key attestation JWT (parsed payload)", parseJwtPayload(keyAttestationJwt));
                }

            } else if (ProofType.ATTESTATION.equals(fullContext.proofType) && fullContext.proofJwt != null) {
                info.addOutput("Attestation proof (parsed header)", parseJwtHeader(fullContext.proofJwt));
                info.addOutput("Attestation proof (parsed payload)", parseJwtPayload(fullContext.proofJwt));
            }

            info.addOutput(    "Credential response", credentialResponseStr);

            return info;
        } catch (Exception ioe) {
            throw new MyException("Unexpected exception when preparing/sending credential request: " + ioe.getMessage(), ioe);
        }
    }

    private boolean checkAttestationKeyPresentIfNeeded(OID4VCIContext oid4vciCtx) {
        // Guard: attestation proof requires that a key was previously generated
        String proofType = oid4vciCtx.getProofType();
        if (ProofType.ATTESTATION.equals(proofType) && oid4vciCtx.getAttestationKey() == null) {
            return false;
        }
        // Guard: JWT proof with attestation also requires a pre-generated attestation key
        if (ProofType.JWT.equals(proofType) && oid4vciCtx.isUseAttestationForJwtProof() && oid4vciCtx.getAttestationKey() == null) {
            return false;
        }

        // OK
        return true;
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

    private InfoBean handleAIAFlow(ActionHandlerContext actionContext) {
        OID4VCIContext oid4vciCtx = actionContext.getSession().getOrCreateOID4VCIContext();
        collectOID4VCIConfigParams(actionContext.getParams(), oid4vciCtx);

        if (oid4vciCtx.getSelectedCredentialId() == null && oid4vciCtx.getSelectedCredentialId().isBlank()) {
            return new InfoBean("No selected", "Please select OID4VCI credential to be used from available credentials");
        }

        String clientId = actionContext.getSession().getRegisteredClient().getClientId();

        LoginUrlBuilder loginUrl = LoginUtil.getAuthorizationRequestUrl(actionContext.getSession().getOidcConfigContext(), actionContext.getUriInfo(), null);
        VerifiableCredentialOfferActionConfig cfg = getKcActionConfig(oid4vciCtx.getSelectedCredentialId(), clientId, oid4vciCtx.isPreAuthorized());
        String kcAction = getKcActionParameter(cfg);
        loginUrl.kcAction(kcAction);
        String loginUrlStr = loginUrl.build();

        actionContext.getFmAttributes().put(Constants.AUTH_REQUEST_URL, loginUrlStr);
        return new InfoBean(
                "Action config (decoded kc_action parameter)", cfg.toString(),
                "OIDC Authentication Request URL", loginUrlStr);
    }

    private VerifiableCredentialOfferActionConfig getKcActionConfig(String credentialConfigId, String clientId, boolean preAuthorized) {
        VerifiableCredentialOfferActionConfig cfg = new VerifiableCredentialOfferActionConfig();
        cfg.setCredentialConfigurationId(credentialConfigId);
        cfg.setClientId(clientId);
        cfg.setPreAuthorized(preAuthorized);
        return cfg;
    }

    private String getKcActionParameter(VerifiableCredentialOfferActionConfig cfg) {
        try {
            String cfgAsString = cfg.asEncodedParameter();
            return VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID + ":" + cfgAsString;
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to encode action config", ioe);
        }
    }

}
