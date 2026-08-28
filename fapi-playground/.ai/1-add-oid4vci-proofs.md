I want to update "OID4VCI" part of the "fapi-playground" application to support OID4VCI proofs.

### Context

fapi-playground is the simple OIDC (OpenID Connect) application, which works together with the Keycloak server. The [README.md](../README.md) file has instructions
on how to setup the project and run the project together with Keycloak server. The pre-requisite is, that "fapi-playground"
also has dependencies on Keycloak maven artifacts. In the README it mentions that it works with Keycloak 26.6.0, but
fact is, that application works with latest Keycloak main, which can be seen from this URL or eventually on my laptop
from the directory /home/mposolda/IdeaProjects/keycloak . Maybe you are already familiar with Keycloak project as I've used it
already with you. Also note that "fapi-playground" is a maven project and Keycloak
artifacts are available from the local maven repository.

For additional context: The OID4VCI specification is here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html .

### Problem

Right now, the "fapi-playground" application supports registration of OIDC client. After administrator manually updates the
client in Keycloak admin console to support OID4VCI, the user can authenticate, request OID4VCI credential
(usually "education-certificate" credential, which is set in Keycloak in the example realm "test") and finally obtain
verifiable credential by sending the credential request. However, right now, the credential request does not support
`proofs` parameter, which is mentioned in the OID4VCI specification in the section 8.2 .

I want to extend application to introduce another option (probably a combo-box) in the OID4VCI. The combo-box should be something like "OID4VCI proof type" with available values:
- none (default option)
- jwt
- attestation


If it is configured with the option `none`, the fapi-playground application should have same behavior as of now and not
send `proofs` claim in the credential request. However if the checkbox is selected with `jwt` or `attestation`, the `proofs`
of corresponding selected type should be attached.

For the inspiration: The class `OID4VCClient` from the Keycloak codebase has utilities to add `proofs` to the OID4VC credential request. It is used in multiple places of the Keycloak codebase.

---------------

### Generating updates to the README file

Are you please also able to add additional instructions to the README.md file (probably to section "Wallet initiated flow") about
how to use that new switch? I think that generating proof may also need update of the "education-certificate" client scope
in the Keycloak admin console in order to make sure that "education-certificate" credential require proofs.
