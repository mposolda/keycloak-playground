## Presentation about credential proofs and attestations

I need some presentation related to credential proofs and attestations. Ideally few slides in the power-point or libreoffice format, but could be even the text
if you are not able to generate power-point (or libre office) files.

I need 3 parts:
1) Verifiable credential without proof
2) Verifiable credential with proof, but without attestation
3) Verifiable credential with attested proof

I would like to have slides with some summary on how these points above work and what asre the parties involved. Ideally maybe
also with some nice charts about the relationship between those parties. Can maybe also have some charts showin the structure
of Sd-JWT verifiable credential and maybe how credential request looks like.

I can see the parties are:
- Wallet, which generates credential request. Wallet is owner of the proof key
- Issuer, which issues credentials. It verifies proofs (and eventually attestations in case of (3)) . Issuer can be Keycloak server
- Verifier, which verifies the credentials. It may eventually also verify key binding if it is present
- Attester (in case of (3)) - The party, which communicates with Wallet and owns attestation keys.
Attester needs to be trusted by Issuer (Keycloak server) as issuer needs to verify if used attestation keys are correct

Based on those parties, I would like to have:
- What happens in case of (1) - the fact that Proof is not present in the credential request and hence issuer does not verify proofs
and cannot generate key binding to the verifiable credential. Verifier is not able to verify holder key binding (as key binding does not exists)
- What happens in case of (2) - The wallet provides the proof key, but the key is not attested. The issuer can verify the key and use
it for creating key binding for the credential. Also the verifier is then able to verify both the issuer signature as well as the holder key binding/
- What happens in case of (3) - There is also attester, which participates in creating the proof, which is used in the credential request to the issuer.
The issuer needs to verify proof, but also it needs to validate if attestation key is correct and can be trusted by the issuer.
Question: Can verifier differentiate between the cases (2) and (3) and see if the sd-jwt verifiable credential was attested by some
trusted attestation party?

For those parties, I would like you to also draw some charts showing the relationships between the parties and what happens during credential issuance and verification.

I've created directory oid4vci/presentation within the fapi-playground project where I would like to export relevant sources (presentations, charts, pictures).

Some relevant sources, which may help you
- This project (and README.md file)
- The OID4VCI specification https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- Sd-jwt draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/
- Sd-jwt for verifiable credentials draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/

## Fix the credential request

On slide 4 - the credential request is incorrect. See chapter 8 of the OID4VCI specification. Credential request should not
contain `format` or `credential_definition`, but rather `credential_identifier` element?

## Fix the picture on slide 5

Picture on slide 5 has slightly broken arrows. Can you please re-draw this picture? Ideally, can you please use some different
format (maybe SVG) and export the picture into separate file, which would be then included from the HTML file?

## Fix the pictures on slide 6 and 7

It would be nice to export also pictures on slide 6 and on slide 7 to the SVG similarly like you did for the picture from slide 5?
As those pictures also have slightly broken arrows.

## Creating libre office impress presentation

Can you please create new libre office presentation (in the libre office impress format) from the file
credential-proofs-and-attestations.html ? If it helps, I have command "libreoffice" in the terminal.

## Fix the pictures on slide 3 and slide 8

Can you re-generate HTML file and export also pictures from slide 3 and slide 8 into the SVG format?

## Re-create slides

I did some updates in the file `credential-proofs-and-attestations.html` . Can you please take the latest version of the file
and re-generate the pptx and odp presentations from it?