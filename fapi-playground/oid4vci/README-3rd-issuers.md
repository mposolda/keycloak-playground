# Keycloak OID4VCI: other vendors comparison

This document contains some notes about 3rd party OID4VCI issuers

## WSO2

The latest stable WSO2 version 7.2.0 doesn't have support for Verifiable credentials. However the support is available in the
"next" version (7.3.0-Beta1 downloadable from https://github.com/wso2/product-is/releases ).

* Here a quickstart how to run a server and login as an admin to the admin console: https://is.docs.wso2.com/en/next/get-started/quick-set-up/

NOTE: Before running the server, I've added this to `repository/conf/deployment.toml` :
```
[verifiable_credentials]
enable = true
```
Maybe it is not strictly needed, but it helped to see the verifiable credentials and option for creating digital wallet in the application

* In the admin console, it is possible to "Verifiable credential template" as mentioned in [the docs](https://is.docs.wso2.com/en/next/guides/verifiable-credentials/issue-vc/). This is
pretty much similar we have for OID4VCI client scope and there are bit similar settings, however there are less options
in comparison to Keycloak. Important configuration options are "Credential identifier" (maps to `credential_configuration_id` as well as name of the client
scope), user attributes to map to the credential, validity (30 days by default) and format (supported are `dc+sd-jwt` and `jwt_vc_json` like we have).

* It is possible to create application of type `digital wallet application`. This is OIDC client with the possibility to link "Verifiable credential" templates,
which can be requested during OIDC login with the use of `scope` parameter referencing the particular VC. So again similar to Keycloak.

  * When linking wallet application with the VC, it is possible to configure "Role based access control (RBAC)". This allows support
    for the use-case like `User with role "student" is able to obtain VC of type "education-certificate" to the wallet application "my-wallet"`.

* No `pre-authorized grant` support. No `issuer_state` parameter support for `authorization code` grant.

* No support for "personalized" credential offers for the concrete users and concrete clients. There is single credential offer
for the specific credential type, which is supposed to be used by all users and wallets. It is single QR code for credential-type, which
is supposed to be used by everyone. For the details, see below the section "WSO2 credential offer - details"

* It is needed to use 3rd party QR code scanner as WSO2 console itself doesn't support built-in QR-code generator

* Well-known URL available under https://localhost:9443/oid4vci/.well-known/openid-credential-issuer .

* They support integration with some wallets (lissi, heidi, inji). All those wallets require pre-registration of the client
with specific client_id and redirect_uri. But WSO2 support itself doesn't support setting of "client_id" directly in their
admin console. It is needed to use REST API for it...

* Supporting only jwt proof. No support for "attestation"

* No support for "credential permissions" per user (Use-case like `User bob is able to obtain education-certificate credential` )
 
* No support for "credential instances" (No tracking of issued VC at the WSO2 side)

* More details in the verifiable credentials documentation:
  * https://is.docs.wso2.com/en/next/guides/verifiable-credentials/ (Intro about protocol)
  * https://is.docs.wso2.com/en/next/guides/verifiable-credentials/issue-vc/ (How to setup in WSO2)
  * https://is.docs.wso2.com/en/next/references/concepts/oid4vci/ (More details about the protocol, requests etc)

### WSO2 credential offer - details

* WSO2 provide single credential offer for their credential for all users and clients. It can be obtained as an URL directly in the WSO2 admin console.
The URL is "static" URL with something like:
```
openid-credential-offer://?credential_offer_uri=https://localhost:9443/oid4vci/credential-offer/48590b61-f6c8-4bdf-8b5b-132ad5ebfee9
```

When opening https://localhost:9443/oid4vci/credential-offer/48590b61-f6c8-4bdf-8b5b-132ad5ebfee9, I can see static credential offer. Something like:
```
{
  "credential_issuer": "https://localhost:9443/oid4vci",
  "credential_configuration_ids": [
    "wso2-education-cert"
  ],
  "grants": {
    "authorization_code": {
      "authorization_server": "https://localhost:9443/oauth2/token"
    }
  }
}
```

## Authlete

* Very nice documentation with lots of diagrams explaining OID4VCI concepts: https://www.authlete.com/developers/oid4vci/

* Authlete provides just REST API, but does not provide end solution for developer (end-to-end credential issuer and authorization
server). From their docs (Start of chapter 3 - https://www.authlete.com/developers/oid4vci/#3-oid4vci-implementation) : While
most vendors directly provide implementations of frontend servers such as an authorization server, Authlete takes a different
approach. Authlete provides a set of Web APIs with which developers themselves can implement their own frontend servers.
Authlete sits behind such frontend servers and is invisible from end users.

* Authlete provides configuration options for various aspects related to OID4VCI (Duration of the credentials and credential offers, algorithms, pre-authorized code anonymous access supported)


* Servers need to call "Authlete APIs" . Authlete provides API for:
  * informations about credential metadata (OID4VCI issuer metadata endpoint). Returned metadata are dependent on how Authlete is configured

  * REST API for creating/get credential-offer : https://www.authlete.com/developers/oid4vci/#341-the-vcioffercreate-api
    NOTE: For pre-authorized code, they support returning `pre-authorized code` and `tx-code` in same REST response. Not ideal for security (although it is needed in case of Authlete as it does not provide full authorization-server and identity-server, but rather just APIs)
 
  * REST API for the OIDC authentication request, token endpoint and token introspection (OIDC, not OID4VCI specific) 
  
  * REST API for credential request and sending back the credential from Authlete

* On the side of OIDC client, there is switch "Credential response encrypted", which specifies if response to this client must be always encrypted.
  
* Authlete API does not have support for storage/tracking of issued credential instances to concrete users. But in theory, it might be up to the server to store it itself (but this would defeat the purpose of delegating the OID4VCI backend handling to Authlete).

* Authlete API has support for storing of credential-offers, which were created by the REST API. But Authlete does not have support for "The user john has permission to obtain VC of type `education-certificate`. It might be again up to the application to handle this and create credential-offer just for the users, which are supposed to have the permissions. This means that permissions might not be handled on the Authlete side, but on the Authorization server side)

* Authlete has some support for client-attestation client authentication

* Support for mdoc credential format (in addition to sd-jwt and jwt_vc_json)

* Section 3.7 contains support for configuration in the management console: https://www.authlete.com/developers/oid4vci/#37-configure-oid4vci-in-the-authlete-management-console

* Demos https://www.authlete.com/developers/oid4vci/#4-oid4vci-demo . Provided demos are:
  * Pre-Authorized Code Flow + Key Proof + SD-JWT VC 
  * Authorization Code Flow + PAR + DPoP + mdoc

## Mattr (WiP)

Most important https://learn.mattr.global/docs/issuance/implementation

* When generating a credential offer, issuers can influence which wallet applications are able to claim the offer and how the user experience flows.
In other words, there is support for `User has permission to obtain credential X just for specific wallet Y`

* Support for credentials status (Tracking of issued VC for individual users). Support for transaction status draft specification.


