package org.keycloak.example.oid4vci;

import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.common.util.Base64Url;
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
import org.keycloak.util.JsonSerialization;

/**
 * Utility for generating OID4VCI holder-binding proofs (jwt and attestation).
 */
public final class ProofUtil {

    private ProofUtil() {
    }

    /**
     * Generate a {@link Proofs} object of the requested type.
     *
     * @param proofType                 the requested proof type ("jwt" or "attestation")
     * @param audience                  the credential-issuer URL used as JWT audience
     * @param cNonce                    the c_nonce value obtained from the nonce endpoint
     * @param attestationKey            pre-generated attestation key (required when proofType is "attestation",
     *                                  or when proofType is "jwt" and useAttestationForJwtProof is true)
     * @param useAttestationForJwtProof when true and proofType is "jwt", embeds a {@code key_attestation}
     *                                  header into the JWT proof signed by the attestation key
     * @return a populated {@link Proofs} ready to attach to a credential request
     */
    public static Proofs buildProofs(String proofType, String audience, String cNonce, KeyWrapper proofKey, KeyWrapper attestationKey, boolean useAttestationForJwtProof) {
        switch (proofType) {
            case ProofType.JWT -> {
                String jwtProof = useAttestationForJwtProof
                        ? generateJwtProofWithKeyAttestation(audience, cNonce, proofKey, attestationKey)
                        : generateJwtProof(audience, cNonce, proofKey);
                return new Proofs().setJwt(List.of(jwtProof));
            }
            case ProofType.ATTESTATION -> {
                if (attestationKey == null) {
                    throw new IllegalStateException("Please generate and configure attestation key before sending an attestation proof");
                }
                String attestationJwt = generateAttestationProof(cNonce, proofKey, attestationKey);
                return new Proofs().setAttestation(List.of(attestationJwt));
            }
            default -> throw new IllegalArgumentException("Unsupported proof type: " + proofType);
        }
    }

    // -------------------------------------------------------------------------
    // JWT proof
    // -------------------------------------------------------------------------

    private static String generateJwtProof(String audience, String nonce, KeyWrapper proofKey) {
        JWK jwk = JWKBuilder.create()
                .kid(proofKey.getKid())
                .ec(proofKey.getPublicKey());
        jwk.setAlgorithm(proofKey.getAlgorithm());

        // Work on a copy so we don't mutate the stored proofKey's kid
        KeyWrapper signingKey = proofKey.cloneKey();
        signingKey.setKid(null); // no kid – embed JWK in header instead

        AccessToken token = new AccessToken();
        token.addAudience(audience);
        token.setNonce(nonce);
        token.issuedNow();

        return new JWSBuilder()
                .type(JwtProofValidator.PROOF_JWT_TYP)
                .jwk(jwk)
                .jsonContent(token)
                .sign(new ECDSASignatureSignerContext(signingKey));
    }

    /**
     * Generate a JWT proof that embeds a {@code key_attestation} header signed by the attestation key.
     * <p>
     * The structure follows the OID4VCI specification and Keycloak's
     * {@code JwtProofValidator}: a fresh EC proof key is generated, the attestation key signs
     * an inner attestation JWT that attests this proof key, and the attestation JWT string is
     * placed in the {@code key_attestation} header of the outer JWT proof.
     * </p>
     */
    private static String generateJwtProofWithKeyAttestation(String audience, String nonce, KeyWrapper proofKey, KeyWrapper attestationKey) {
        // 1. Use the provided proof key
        JWK proofJwk = JWKBuilder.create().ec(proofKey.getPublicKey());
        proofJwk.setKeyId(proofKey.getKid());
        proofJwk.setAlgorithm(proofKey.getAlgorithm());

        // 2. Build the inner key-attestation JWT signed by the attestation key
        long now = System.currentTimeMillis() / 1000;
        KeyAttestationJwtBody attestationBody = new KeyAttestationJwtBody();
        attestationBody.setIat(now);
        attestationBody.setExp(now + 3600);
        attestationBody.setNonce(nonce);
        attestationBody.setAttestedKeys(List.of(proofJwk));

        String innerAttestationJwt = new JWSBuilder()
                .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                .kid(attestationKey.getKid())
                .jsonContent(attestationBody)
                .sign(new ECDSASignatureSignerContext(attestationKey));

        // 3. Build the outer JWT proof with key_attestation header
        AccessToken token = new AccessToken();
        token.addAudience(audience);
        token.setNonce(nonce);
        token.issuedNow();

        Map<String, Object> header = new HashMap<>();
        header.put("alg", proofKey.getAlgorithm());
        header.put("typ", JwtProofValidator.PROOF_JWT_TYP);
        header.put("jwk", proofJwk);
        header.put("key_attestation", innerAttestationJwt);

        // Work on a copy so we don't mutate the stored proofKey's kid
        KeyWrapper signingKey = proofKey.cloneKey();
        signingKey.setKid(null);

        return new JWSBuilder() {
            @Override
            protected String encodeHeader(String sigAlgName) {
                try {
                    return Base64Url.encode(JsonSerialization.writeValueAsBytes(header));
                } catch (Exception e) {
                    throw new RuntimeException("Failed to encode JWT proof header with key_attestation", e);
                }
            }
        }.jsonContent(token).sign(new ECDSASignatureSignerContext(signingKey));
    }

    // -------------------------------------------------------------------------
    // Attestation proof
    // -------------------------------------------------------------------------

    private static String generateAttestationProof(String nonce, KeyWrapper proofKey, KeyWrapper attestationKey) {
        // The provided proof key is embedded in the attestation body
        JWK proofJwk = JWKBuilder.create()
                .kid(proofKey.getKid())
                .ec(proofKey.getPublicKey());

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

    /**
     * Generate a fresh EC key pair (ES256 / P-256) suitable for use as an attestation key or proof key.
     *
     * @attestation Flag to specify whether this should be attestation key (flag should be true) or proof key (flag should be false)
     */
    public static KeyWrapper createEcKeyPair(boolean attestation) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyIntegration.PROVIDER);
            kpg.initialize(256);
            var kp = kpg.generateKeyPair();

            KeyWrapper kw = new KeyWrapper();
            String kid = attestation ? "attestation-key-" + System.nanoTime() : "proof-key-" + System.nanoTime();
            kw.setKid(kid);
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
