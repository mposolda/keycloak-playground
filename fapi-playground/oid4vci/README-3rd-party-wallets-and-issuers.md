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
*NOTE: New version released on Apr 20 (3.1.3 (17277) . TODO: Test with that  version and update below instructions.*

2) **Keycloak on real host** - Lissi wallet requires Keycloak running on the HTTPS and real host with widely known certificate. Here the example how to
run Keycloak on real host with the use of https://localhost.run/docs/http-tunnels

* Run this in the linux terminal `ssh -R 80:localhost:8080 localhost.run`

* Copy/paste the URL from the terminal above and start Keycloak with something like:
```
./kc.sh start --hostname https://2ce816c8200c75.lhr.life --http-enabled true \
--proxy-headers xforwarded --features=oid4vc-vci,oid4vc-vci-preauth-code
```

* Keycloak should be up and running on URL like https://2ce816c8200c75.lhr.life with the real certificate

3) **Import the realm** from [fapi-playground](singleFile-realm.json). Most important points:

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

* Open https://2ce816c8200c75.lhr.life/realms/test/account with browser on your laptop

* After redirect to Keycloak, the login screen is being displayed and browser contains OIDC authentication URL. Add this parameter to the end of the browser URL and refresh the browser URL with this parameter:
```
&kc_action=verifiable_credential_offer:eyJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25faWQiOiJlZHVjYXRpb24tY2VydGlmaWNhdGUtY29uZmlnLWlkIiwiY2xpZW50X2lkIjoiOWM0ODFkYzMtMmFkMC00ZmUwLTg4MWQtYzMyYWQwMmZlMGZjIiwicHJlX2F1dGhvcml6ZWQiOnRydWV9
```
    
   NOTE: The `kc_action` parameter above is parameterized action for displaying credential-offer. The parameter is base64-encoded value of the credential-offer config, which looks like this (in the plain code):
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
see the credential displayed successfully (Probably looks like the bug in the Lissi wallet).


5) **Authorization code grant**

* Same steps like for like "Pre-authorized grant", but use this `kc_action` for authorization_code (parameter "pre-authorized" is false within this request)

```
&kc_action=verifiable_credential_offer:eyJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25faWQiOiJlZHVjYXRpb24tY2VydGlmaWNhdGUtY29uZmlnLWlkIiwiY2xpZW50X2lkIjoiOWM0ODFkYzMtMmFkMC00ZmUwLTg4MWQtYzMyYWQwMmZlMGZjIiwicHJlX2F1dGhvcml6ZWQiOmZhbHNlfQ==
```

* After scan, it is also needed to authenticate user in the mobile browser. As `authorization code` grant runs the full OIDC
login flow with the "authorization code" grant.

NOTE (for the reference): Lissi wallet authorization_code uses PAR requests to start the authorization-code flow
