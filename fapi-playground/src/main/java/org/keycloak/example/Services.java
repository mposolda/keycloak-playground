package org.keycloak.example;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.example.util.FreeMarkerUtil;
import org.keycloak.example.util.MutualTLSUtils;
import org.keycloak.example.util.MyConstants;
import org.keycloak.example.util.OAuthClient;
import org.keycloak.example.util.PersistenceProvider;
import org.keycloak.example.util.SessionData;
import org.keycloak.models.Constants;

import javax.net.ssl.SSLContext;

import static org.keycloak.example.util.MyConstants.REALM_NAME;
import static org.keycloak.example.util.MyConstants.SERVER_ROOT;

/**
 * Application-scoped stuff
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class Services {

    private static final Services instance = new Services();
    static {
        // Initialization
        instance.session = createSession();
    }

    private Services() {
        CryptoIntegration.init(Services.class.getClassLoader());
    }



    public static Services instance() {
        return instance;
    }

    private final FreeMarkerUtil freeMarker = new FreeMarkerUtil();
    private volatile OAuthClient oauthClient;
    private volatile CloseableHttpClient httpClient;

    private SessionData session;

    private static SessionData createSession() {
        SessionData s = new SessionData();
        PersistenceProvider.load(s);
        return s;
    }


    public FreeMarkerUtil getFreeMarker() {
        return freeMarker;
    }

    public CloseableHttpClient getHttpClient() {
        if (httpClient == null) {
            synchronized (this) {
                httpClient = MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore();
            }
        }
        return httpClient;
    }

    public OAuthClient getOauthClient() {
        if (oauthClient == null) {
            synchronized (this) {
                oauthClient = new OAuthClient(SERVER_ROOT, getHttpClient())
                        .realm(REALM_NAME);
//                oauthClient.init();
            }
        }
        return oauthClient;
    }

    public SessionData getSession() {
        return session;
    }

    public Keycloak getAdminClient() {
        String accessToken = session.getTokenRequestCtx().getResponse().getAccessToken();
        KeycloakBuilder builder = KeycloakBuilder.builder()
                .serverUrl(SERVER_ROOT)
                .resteasyClient(Keycloak.getClientProvider().newRestEasyClient(null, null, true)) // TODO Proper SSL context
                .realm(REALM_NAME)
                .authorization(accessToken);
       return builder.build();
    }

//    public void setSession(SessionData session) {
//        this.session = session;
//    }
}
