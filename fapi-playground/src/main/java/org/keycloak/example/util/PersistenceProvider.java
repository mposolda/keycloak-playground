package org.keycloak.example.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.example.oid4vci.OID4VCIContext;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

import java.io.File;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Handles persistence of selected {@link SessionData} fields across application restarts.
 * Data is stored as JSON in {@code data/client-data.json} relative to the working directory.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PersistenceProvider {

    private static final Logger log = Logger.getLogger(PersistenceProvider.class);

    private static final String DATA_DIR = "data";
    private static final String CLIENT_DATA_FILE      = DATA_DIR + "/client-data.json";
    private static final String ATTESTATION_DATA_FILE = DATA_DIR + "/attestation-data.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Called at startup. Ensures the {@code data/} directory exists and, if
     * {@code data/client-data.json} is present, pre-loads the persisted fields
     * into {@code session}.
     */
    public static void load(SessionData session) {
        File dataDir = new File(DATA_DIR);
        if (!dataDir.exists()) {
            if (dataDir.mkdirs()) {
                log.infof("Created data directory: %s", dataDir.getAbsolutePath());
            } else {
                log.warnf("Could not create data directory: %s", dataDir.getAbsolutePath());
            }
            return;
        }

        File file = new File(CLIENT_DATA_FILE);
        if (!file.exists()) {
            log.infof("Client data does not exists yet. Skip loading");
            return;
        }

        log.infof("Loading existing client data");

        try {
            ObjectNode root = (ObjectNode) MAPPER.readTree(file);

            // Restore ClientConfigContext
            if (root.has("clientConfigContext")) {
                ObjectNode ctx = (ObjectNode) root.get("clientConfigContext");
                String initialAccessToken = ctx.has("initialAccessToken") ? ctx.get("initialAccessToken").asText(null) : null;
                String clientAuthMethod   = ctx.has("clientAuthMethod")   ? ctx.get("clientAuthMethod").asText("none") : "none";
                boolean generateJwks      = ctx.has("generateJwks") && ctx.get("generateJwks").asBoolean();
                session.setClientConfigContext(new ClientConfigContext(initialAccessToken, clientAuthMethod, generateJwks));
            }

            // Restore registered client
            if (root.has("registeredClient")) {
                OIDCClientRepresentation registeredClient =
                        MAPPER.treeToValue(root.get("registeredClient"), OIDCClientRepresentation.class);
                session.setRegisteredClient(registeredClient);
                OAuthClientUtil.setupOAuthClient(session, registeredClient.getClientId(), registeredClient.getClientSecret());
            }

            // Restore keys
            if (root.has("keys")) {
                ObjectNode keysNode = (ObjectNode) root.get("keys");
                String privatePem    = keysNode.get("privateKey").asText();
                String publicPem     = keysNode.get("publicKey").asText();
                String keyType       = keysNode.get("keyType").asText();
                String keyAlgorithm  = keysNode.has("keyAlgorithm") ? keysNode.get("keyAlgorithm").asText(null) : null;
                String keyUseName    = keysNode.get("keyUse").asText();

                PrivateKey privateKey = PemUtils.decodePrivateKey(privatePem);
                PublicKey  publicKey  = PemUtils.decodePublicKey(publicPem, keyType);
                KeyPair    keyPair    = new KeyPair(publicKey, privateKey);
                KeyUse     keyUse     = KeyUse.valueOf(keyUseName);

                KeysWrapper keys = new KeysWrapper();
                keys.loadFromPersisted(keyPair, keyType, keyAlgorithm, keyUse);
                session.setKeys(keys);
            }

            log.infof("Loaded persisted session data from %s", file.getAbsolutePath());
        } catch (Exception e) {
            log.warnf(e, "Failed to load persisted session data from %s — starting with empty session", file.getAbsolutePath());
        }
    }

    /**
     * Called after a successful client registration. Writes the three persisted
     * fields from {@code session} to {@code data/client-data.json}.
     */
    public static void save(SessionData session) {
        try {
            File dataDir = new File(DATA_DIR);
            if (!dataDir.exists()) {
                dataDir.mkdirs();
            }

            log.infof("Saving client data");

            ObjectNode root = MAPPER.createObjectNode();

            // Persist ClientConfigContext
            ClientConfigContext ctx = session.getClientConfigContext();
            if (ctx != null) {
                ObjectNode ctxNode = root.putObject("clientConfigContext");
                ctxNode.put("initialAccessToken", ctx.getInitialAccessToken());
                ctxNode.put("clientAuthMethod",   ctx.getClientAuthMethod());
                ctxNode.put("generateJwks",       ctx.isGenerateJwks());
            }

            // Persist registered client
            if (session.getRegisteredClient() != null) {
                root.set("registeredClient", MAPPER.valueToTree(session.getRegisteredClient()));
            }

            // Persist keys as PEM
            KeysWrapper keys = session.getKeys();
            if (keys != null && keys.getClientData().getKeyPair() != null) {
                KeysWrapper.OIDCClientData cd = keys.getClientData();
                ObjectNode keysNode = root.putObject("keys");
                keysNode.put("privateKey",   PemUtils.encodeKey(cd.getKeyPair().getPrivate()));
                keysNode.put("publicKey",    PemUtils.encodeKey(cd.getKeyPair().getPublic()));
                keysNode.put("keyType",      cd.getKeyType());
                keysNode.put("keyAlgorithm", cd.getKeyAlgorithm());
                keysNode.put("keyUse",       cd.getKeyUse().name());
            }

            MAPPER.writerWithDefaultPrettyPrinter().writeValue(new File(CLIENT_DATA_FILE), root);
            log.infof("Persisted session data to %s", CLIENT_DATA_FILE);
        } catch (Exception e) {
            log.warnf(e, "Failed to persist session data to %s", CLIENT_DATA_FILE);
        }
    }

    /**
     * Persists the attestation key from {@code oid4vciCtx} to {@code data/attestation-data.json}.
     * Called each time a new attestation key is generated.
     */
    public static void saveAttestationKey(OID4VCIContext oid4vciCtx) {
        KeyWrapper key = oid4vciCtx.getAttestationKey();
        if (key == null) {
            return;
        }
        try {
            File dataDir = new File(DATA_DIR);
            if (!dataDir.exists()) {
                dataDir.mkdirs();
            }

            ObjectNode root = MAPPER.createObjectNode();
            root.put("kid",       key.getKid());
            root.put("algorithm", key.getAlgorithm());
            root.put("keyType",   key.getType());
            root.put("privateKey", Base64.getEncoder().encodeToString(key.getPrivateKey().getEncoded()));
            root.put("publicKey",  Base64.getEncoder().encodeToString(key.getPublicKey().getEncoded()));

            MAPPER.writerWithDefaultPrettyPrinter().writeValue(new File(ATTESTATION_DATA_FILE), root);
            log.infof("Persisted attestation key to %s", ATTESTATION_DATA_FILE);
        } catch (Exception e) {
            log.warnf(e, "Failed to persist attestation key to %s", ATTESTATION_DATA_FILE);
        }
    }

    /**
     * Loads the attestation key from {@code data/attestation-data.json} (if present) into
     * {@code oid4vciCtx}. Called once at application startup.
     */
    public static void loadAttestationKey(OID4VCIContext oid4vciCtx) {
        File file = new File(ATTESTATION_DATA_FILE);
        if (!file.exists()) {
            log.infof("Attestation data file does not exist yet. Skip loading");
            return;
        }

        try {
            ObjectNode root = (ObjectNode) MAPPER.readTree(file);

            String kid       = root.get("kid").asText();
            String algorithm = root.get("algorithm").asText();
            String keyType   = root.get("keyType").asText();

            // Note: This is specific to "EC" keys
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(root.get("privateKey").asText()));
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey privateKey = kf.generatePrivate(privateKeySpec);

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(root.get("publicKey").asText()));
            PublicKey publicKey = kf.generatePublic(publicKeySpec);

            KeyWrapper kw = new KeyWrapper();
            kw.setKid(kid);
            kw.setAlgorithm(algorithm);
            kw.setType(keyType);
            kw.setUse(KeyUse.SIG);
            kw.setPrivateKey(privateKey);
            kw.setPublicKey(publicKey);

            oid4vciCtx.setAttestationKey(kw);
            log.infof("Loaded persisted attestation key (kid=%s) from %s", kid, file.getAbsolutePath());
        } catch (Exception e) {
            log.warnf(e, "Failed to load attestation key from %s — starting without attestation key", file.getAbsolutePath());
        }
    }
}
