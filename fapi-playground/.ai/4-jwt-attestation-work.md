## JWT Attestation

As an additional step, I want that also the `OID4VC Proof type` of `jwt` should be able to use the attestation key generated
in the `OID4VCIContext.attestationKey`.

Please update the application to do the following:

- Add the checkbox `Use attestation for JWT proofs` into the `OID4VCI` section. It should be off by default

- When it is OFF, the behavior for `jwt` proof should be the same as of now

- When it is ON and the attestation key was not yet generated, it should display the same error message like displayed
for the `attestation` proof in case of missing generated attestation key

- When it is ON and the attestation key was generated, the attestation should be attached to the `jwt` proof. Keycloak testsuite
has some tests on how to use attestation key with the `jwt` proof and this should be supported in the `OID4VCClient`.
Also it is described in the OID4VCI specification. Can you figure it and update application accordingly?

- Finally, please update README.md for the `jwt` attestation proof and add those details about the attestation key.
