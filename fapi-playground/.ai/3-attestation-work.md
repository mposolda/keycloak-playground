### Working attestation

I have a problem in the `fapi-playground` application for the case when `OID4VC proof type` is configured with the type
`attestation`. When I try to send the request to Keycloak with such an attestation, Keycloak returns credential response with
an error like this `"error" : "invalid_proof"` and 
`"errorDescription" : "Key with kid 'proof-key-823895213619792' not found in trusted key registry"`

I think that in this particular case, it is needed that there is a need that Keycloak must have Identity provider configured
with the attestation key, which is used for creating of `attestation` proof. For this to work, I will possibly need something
like this:

1) New button `Generate attestation key` in the section `OID4VCI`. When this button is clicked, fapi-playground should generate
new key pair and the keypair (pretty much by `ProofUtil.createEcKeyPair()` ). The key should be saved in the `OID4VCIContext`

2) The `InfoBean` should display some text like `Attestation key generated` and it should show the public key of the generated
attestation key in the JWKS format

3) Later, when I want to send `Credential request` of type `attestation`, the previously generated key should be used instead of
always generating new key. When the key was not yet previously generated and the `OID4VC proof type` is selected as `attestation`, then
`Credential request` should show some error like `Please generate and configure attestation key` .

4) README instructions should be updated for the `attestation` type. It should also mention that after step (2) above, administrator
needs to configure `Trusted key` identity provider in Keycloak. That provider should be configured with the JWKS displayed by
the `fapi-playground` in the step 2. Also client should be configured in Keycloak admin console to reference that IDP. For some more reference, the Keycloak documentation has some instructions on how to configure
the trusted-key IDP (this documentation might be referenced from this README for more details). The documentation is
on this link: https://www.keycloak.org/docs/nightly/server_admin/index.html#_oid4vci_proofs

-----------

### Persistence of attestation key

As additional thing, I want also "attestation key", which was generated from the application by the button `Generate attestation key` to
be persisted and to survive restarts of the `fapi-playground` application. In addition to the file `client-data.json` , it can
be good to create new file `attestation-data.json` with the key inside the directory `data`. Always when new attestation key is generated, it should be persisted into this file.
During startup of the application, the key should be preloaded to the `OID4VCIContext` similarly like is done for the client (that client, which is read from `client-data.json` file).
