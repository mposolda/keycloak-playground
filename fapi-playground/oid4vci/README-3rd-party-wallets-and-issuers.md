# Keycloak OID4VCI: Wallets integration, other vendors comparison

This document contains some notes for:

* 3rd party OID4VCI Wallets, their integration with Keycloak
* 3rd party OID4VCI issuers

## 3rd party Wallets

### Lissi Wallet

It was possible to successfully integrate Keycloak 26.6.0 with Lissi ID Wallet android application with the use of both
`authorization_code` and `pre-authorized code` flows.

* It seems that Lissi wallet still uses older version of OID4VCI specification (not the OID4VCI 1.0.Final).

* Lissi wallet mentions in their [Terms and conditions](https://docs.lissi.id/legal/lissi-id-wallet-allgemeine-geschaftsbedingungen-te) (in german) that it is just for testing purposes for now.

* It seems that lissi wallet uses hardcoded clientId and redirect-url in their. This client is needed to be pre-configured on the
Keycloak side (See steps below for the details). It looks that same applies for some other wallets according to the [WSO2 documentation](https://is.docs.wso2.com/en/next/guides/verifiable-credentials/issue-vc/#tested-wallets), which describe
some steps for the integration with those wallets.

#### Steps for integration Keycloak 26.6.0 with Lissi ID Wallet

1) **Install Lissi ID Wallet app on the android phone**. Tested with version 3.0.1 (15828). Needed to setup PIN and biometrics in the application.
*NOTE: New version 3.1.3 (17277) released on Apr 20 2026. TODO: Test with that  version and update below instructions.*

2) **Keycloak on real host** - Lissi wallet requires Keycloak running on the HTTPS and real host with the proper certificate. Here the example how to
run Keycloak on real host with the use of https://localhost.run/docs/http-tunnels

* Run this in the linux terminal `ssh -R 80:localhost:8080 localhost.run`

* Copy/paste the URL from the terminal above and start Keycloak with something like:
```
./kc.sh start --hostname https://2ce816c8200c75.lhr.life --http-enabled true \
--proxy-headers xforwarded --features=oid4vc-vci,oid4vc-vci-preauth-code
```

* Keycloak should be up and running on URL like https://2ce816c8200c75.lhr.life with the real certificate

3) **Import the realm** from [fapi-playground](singleFile-realm.json) to your Keycloak. Most important points:

* Realm contains pre-defined OID4VCI client scope `education-certificate` 
* It contains some pre-defined users. Especially `john-doh@localhost` used below, which has all required attributes (university and education-certificate).
* It looks that lissi wallet uses OIDC client with hardcoded client_id, which is supposed to be available on the OIDC server. Client
already present in the mentioned realm. For the reference, here is the setup of the client (in case manual setup desired):
    * Client ID: `9c481dc3-2ad0-4fe0-881d-c32ad02fe0fc`
    * Valid redirect URIs: `https://oob.lissi.io/vci-cb`
    * Valid post logout redirect URIs: `+` 
    * Valid web origins: `+`
    * Public client: true
    * Standard flow enabled: true
    * Enable OID4VCI (in the tab "Advanced" in the admin console): `ON`
    * Client scope `Education-certificate` should be added as `optional` to the client

4) **Pre-authorized code grant**

* Open URL similar to https://2ce816c8200c75.lhr.life/realms/test/account with browser on your laptop

* After redirect to Keycloak, the login screen is being displayed and browser contains OIDC authentication URL. Add this parameter to the end of the browser URL and refresh the browser URL:
```
&kc_action=verifiable_credential_offer:eyJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25faWQiOiJlZHVjYXRpb24tY2VydGlmaWNhdGUtY29uZmlnLWlkIiwiY2xpZW50X2lkIjoiOWM0ODFkYzMtMmFkMC00ZmUwLTg4MWQtYzMyYWQwMmZlMGZjIiwicHJlX2F1dGhvcml6ZWQiOnRydWV9
```
    
   NOTE: The `kc_action` parameter above is parameterized AIA for displaying credential-offer. The parameter is base64-encoded value of the credential-offer config, which looks like this (in the plain code):
```
{
  "credential_configuration_id":"education-certificate-config-id",
  "client_id":"9c481dc3-2ad0-4fe0-881d-c32ad02fe0fc",
  "pre_authorized":true
}
```

* Fill username/password `john-doh@localhost` / `password` . Should be redirected to the screen with education-certificate credential offer

* Scan the displayed QR code with the Lissi ID wallet application from your mobile phone

* Confirm the credential offer for education-certificate in your mobile. At this point, there were some errors displayed in the application,
however when checking Keycloak events in the admin console, I can see that all events are successful (especially credential-offer creation events, 
pre-authorized code token request and finally credential event). After restart of the Lissi ID-wallet application on my mobile, I can
see the credential displayed successfully (Looks like the bug in the Lissi wallet that application restart is needed).


5) **Authorization code grant**

* Same steps like for like "Pre-authorized grant", but use this `kc_action` for authorization_code (parameter "pre-authorized" is false within this request)

```
&kc_action=verifiable_credential_offer:eyJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25faWQiOiJlZHVjYXRpb24tY2VydGlmaWNhdGUtY29uZmlnLWlkIiwiY2xpZW50X2lkIjoiOWM0ODFkYzMtMmFkMC00ZmUwLTg4MWQtYzMyYWQwMmZlMGZjIiwicHJlX2F1dGhvcml6ZWQiOmZhbHNlfQ==
```

* After scan the QR code, it is also needed to authenticate Keycloak user in the mobile browser. As `authorization code` grant runs the full OIDC
login flow with the "authorization code" grant. After login of the user and confirm credential offer in the Lissi wallet, there are again errors
similarly like for pre-authorized grant. But restart of the wallet helped and can see the credential.

NOTE (for the reference): Lissi wallet authorization_code uses PAR requests to start the authorization-code flow

**TODO:** 
* Use the latest lissi ID-wallet application
* Make this working with JWT `proofs`

### Heidi wallet

TODO

### Other wallets

maybe "Inji" and/or "Valera"

TODO

## 3rd party OIDC issuers

### WSO2

The latest stable WSO2 version 7.2.0 doesn't have support for Verifiable credentials. However the support is available in the
"next" version (7.3.0-Beta1 downloadable from https://github.com/wso2/product-is/releases ).

* Here a quickstart how to run a server and login as an admin to the admin console: https://is.docs.wso2.com/en/next/get-started/quick-set-up/

NOTE: Before running the server, I've added this to `repository/conf/deployment.toml` :
```
[verifiable_credentials]
enable = true
```
Maybe it is not strictly needed, but it helped to see the verifiable credentials and option for creating digital wallet in the application

* In the 7.3.0-Beta1 version, I was able to go to admin console "Verifiable credentials" tab and create "Verifiable credential template" . This is
pretty much similar we have for OID4VCI client scope and there are bit similar settings, however there are less options
in comparison to Keycloak. Important configuration options are "Credential identifier" (maps to `credential_configuration_id` as well as name of the client
scope), user attributes to map to the credential, validity (30 days by default) and format (supported are `dc+sd-jwt` and `jwt_vc_json` like we have).


* WSO2 provide single credential offer for their credential for all users and clients. It can be obtained as an URL directly in the admin console. The URL is "static" URL with something like:
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
This means there are not concrete credential offers for the concrete clients.

* It is needed to use 3rd party QR code scanner as WSO2 console itself doesn't support built-in QR-code generator

* No `pre-authorized grant` support. No `issuer_state` parameter support for `authorization code` grant.

* Well-known URL available under https://localhost:9443/oid4vci/.well-known/openid-credential-issuer .

* They support integration with some wallets (lissi, heidi, inji). All those wallets require pre-registration of the client
with specific client_id and redirect_uri. But WSO2 support itself doesn't support setting of "client_id" directly in their
admin console. It is needed to use REST API for it...

* Supporting only jwt proof. No support for "attestation"

* No support for personalized "Credential offers", "credential permissions" or "credential instances" TODO: Check policies

* More details in the verifiable credentials documentation:
  * https://is.docs.wso2.com/en/next/guides/verifiable-credentials/ (Intro about protocol)
  * https://is.docs.wso2.com/en/next/guides/verifiable-credentials/issue-vc/ (How to setup in WSO2)
  * https://is.docs.wso2.com/en/next/references/concepts/oid4vci/ (More details about the protocol, requests etc)


