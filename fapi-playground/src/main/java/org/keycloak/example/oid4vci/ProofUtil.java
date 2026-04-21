package org.keycloak.example.oid4vci;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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

        // Use x5c header if attestation key has a certificate chain; otherwise use kid
        String innerAttestationJwt = buildAttestationJwt(attestationBody, attestationKey);

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

        // Use x5c header if attestation key has a certificate chain; otherwise use kid
        return buildAttestationJwt(body, attestationKey);
    }

    /**
     * Build an attestation JWT. Uses {@code x5c} header when the attestation key carries a
     * certificate chain (set by "Generate attestation certificates"); falls back to {@code kid}.
     * <p>
     * When {@code x5c} is used, {@code kid} is intentionally omitted: {@link JWSBuilder} auto-fills
     * {@code kid} from the signer's {@link KeyWrapper#getKid()} during {@code sign()}, so we sign
     * with a kid-less clone to prevent it leaking into the header alongside {@code x5c}.
     */
    private static String buildAttestationJwt(KeyAttestationJwtBody body, KeyWrapper attestationKey) {
        List<X509Certificate> certChain = attestationKey.getCertificateChain();
        if (certChain != null && !certChain.isEmpty()) {
            // Omit the trust-anchor certificate
            List<X509Certificate> certChainCopy = List.of(certChain.get(0));

            // Clone to avoid mutating the stored key; clear kid so JWSBuilder doesn't add it
            KeyWrapper signingKey = attestationKey.cloneKey();
            signingKey.setKid(null);
            return new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .x5c(certChainCopy) // Trust-anchor certificate is omitted from x5c (using trust-anchor is not HAIP compliant)
//                    .x5c(certChain)
                    .jsonContent(body)
                    .sign(new ECDSASignatureSignerContext(signingKey));
        } else {
            return new JWSBuilder()
                    .type(AttestationValidatorUtil.ATTESTATION_JWT_TYP)
                    .kid(attestationKey.getKid())
                    .jsonContent(body)
                    .sign(new ECDSASignatureSignerContext(attestationKey));
        }
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

    /**
     * Generate a self-signed root CA X.509 certificate for the given key pair.
     * <p>
     * The certificate is built as a V3 cert with:
     * <ul>
     *   <li>{@code BasicConstraints(cA=true)} — satisfies {@code getBasicConstraints() >= 0}</li>
     *   <li>{@code KeyUsage(keyCertSign | cRLSign)} — satisfies the key-usage check for certificate signing</li>
     * </ul>
     * Both constraints are required by Keycloak's {@code X509TrustMaterial.validateTrustAnchor}.
     */
    public static X509Certificate createSelfSignedCaCertificate(java.security.KeyPair keyPair, String subjectDn) {
        try {
            X500Name dn = new X500Name(subjectDn);
            BigInteger serial = new BigInteger(128, new SecureRandom());
            Date notBefore = new Date(System.currentTimeMillis());
            Date notAfter  = new Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(dn, serial, notBefore, notAfter, dn, spki);

            // BasicConstraints: cA = true (pathLenConstraint not set → unlimited)
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

            // KeyUsage: keyCertSign + cRLSign (bit 5 = keyCertSign, checked at index 5)
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyIntegration.PROVIDER)
                    .build(keyPair.getPrivate());

            return new JcaX509CertificateConverter()
                    .setProvider(BouncyIntegration.PROVIDER)
                    .getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate self-signed CA certificate", e);
        }
    }

    /**
     * Generate a leaf (end-entity) X.509 certificate signed by the given CA.
     * <p>
     * The certificate is built as a V3 cert with:
     * <ul>
     *   <li>{@code BasicConstraints(cA=false)} — satisfies {@code getBasicConstraints() < 0} (end entity)</li>
     *   <li>{@code KeyUsage(digitalSignature)} — bit 0, required by Keycloak's chain-leaf check</li>
     * </ul>
     * Both are required by Keycloak's {@code X509CertificateChainValidator.validateLeafPurpose}.
     */
    public static X509Certificate createLeafCertificate(java.security.KeyPair leafKeyPair, String subjectDn,
                                                         X509Certificate caCert, java.security.PrivateKey caPrivateKey) {
        try {
            // Read the issuer DN directly from the CA cert's DER-encoded subject to preserve
            // the exact RDN order and encoding — avoids the ordering flip that X500Principal.getName()
            // (RFC 2253) would introduce.
            X500Name issuerDn = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            X500Name subjectX500 = new X500Name(subjectDn);
            BigInteger serial = new BigInteger(128, new SecureRandom());
            Date notBefore = new Date(System.currentTimeMillis());
            Date notAfter  = new Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(leafKeyPair.getPublic().getEncoded());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    issuerDn, serial, notBefore, notAfter, subjectX500, spki);

            // BasicConstraints: cA = false — this is an end-entity certificate
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            // KeyUsage: digitalSignature only (bit 0, checked at index 0 by Keycloak)
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyIntegration.PROVIDER)
                    .build(caPrivateKey);

            return new JcaX509CertificateConverter()
                    .setProvider(BouncyIntegration.PROVIDER)
                    .getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate leaf certificate", e);
        }
    }
}
