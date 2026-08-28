package org.keycloak.example.oid4vci;

import java.security.KeyPairGenerator;
import java.util.List;

import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationValidatorUtil;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidator;
import org.keycloak.protocol.oid4vc.model.KeyAttestationJwtBody;
import org.keycloak.protocol.oid4vc.model.Proofs;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.representations.AccessToken;

/**
 * Utility for generating OID4VCI holder-binding proofs (jwt and attestation).
 */
public final class ProofUtil {

    private ProofUtil() {
    }

    /**
     * Generate a {@link Proofs} object of the requested type.
     *
     * @param proofType the requested proof type ("jwt" or "attestation")
     * @param audience  the credential-issuer URL used as JWT audience
     * @param cNonce    the c_nonce value obtained from the nonce endpoint
     * @return a populated {@link Proofs} ready to attach to a credential request
     */
    public static Proofs buildProofs(String proofType, String audience, String cNonce) {
        switch (proofType) {
            case ProofType.JWT -> {
                String jwtProof = generateJwtProof(audience, cNonce);
                return new Proofs().setJwt(List.of(jwtProof));
            }
            case ProofType.ATTESTATION -> {
                String attestationJwt = generateAttestationProof(cNonce);
                return new Proofs().setAttestation(List.of(attestationJwt));
            }
            default -> throw new IllegalArgumentException("Unsupported proof type: " + proofType);
        }
    }

    // -------------------------------------------------------------------------
    // JWT proof
    // -------------------------------------------------------------------------

    private static String generateJwtProof(String audience, String nonce) {
        KeyWrapper keyWrapper = createEcKeyPair();
        keyWrapper.setKid(null); // no kid – embed JWK in header instead

        JWK jwk = JWKBuilder.create().ec(keyWrapper.getPublicKey());
        jwk.setAlgorithm(keyWrapper.getAlgorithm());

        AccessToken token = new AccessToken();
        token.addAudience(audience);
        token.setNonce(nonce);
        token.issuedNow();

        return new JWSBuilder()
                .type(JwtProofValidator.PROOF_JWT_TYP)
                .jwk(jwk)
                .jsonContent(token)
                .sign(new ECDSASignatureSignerContext(keyWrapper));
    }

    // -------------------------------------------------------------------------
    // Attestation proof
    // -------------------------------------------------------------------------

    private static String generateAttestationProof(String nonce) {
        KeyWrapper attestationKey = createEcKeyPair();

        // The attested key (proof key) is embedded in the attestation body
        JWK proofJwk = JWKBuilder.create().ec(createEcKeyPair().getPublicKey());

        long now = System.currentTimeMillis() / 1000;
        KeyAttestationJwtBody body = new KeyAttestationJwtBody();
        body.setIat(now);
        body.setExp(now + 3600);
        body.setNonce(nonce);
        body.setAttestedKeys(List.of(proofJwk));

        return new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .kid(attestationKey.getKid())
                .jsonContent(body)
                .sign(new ECDSASignatureSignerContext(attestationKey));
    }

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    private static KeyWrapper createEcKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyIntegration.PROVIDER);
            kpg.initialize(256);
            var kp = kpg.generateKeyPair();

            KeyWrapper kw = new KeyWrapper();
            kw.setKid("proof-key-" + System.nanoTime());
            kw.setUse(KeyUse.SIG);
            kw.setAlgorithm("ES256");
            kw.setType("EC");
            kw.setPublicKey(kp.getPublic());
            kw.setPrivateKey(kp.getPrivate());
            return kw;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair for proof", e);
        }
    }
}
