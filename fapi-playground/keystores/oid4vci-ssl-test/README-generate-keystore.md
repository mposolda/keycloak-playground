# OID4VCI Keystores setup

Setup of keystores and truststores for make Keycloak and fapi-playground OID4VCI demo working

## Generate keystore for signing credentials

Keystore for signing credentials must be HAIP compliant. Here the setups how to generate infrastructure for this. Assumption is to have `openssl` command installed on Linux
and usable from bash terminal (tested with OpenSSL 3.0.13).

1) Generate root CA E256 private key
```
CURVE=prime256v1
openssl ecparam -name $CURVE -genkey -noout -out rootCA.key
```

2) Generate root CA certificate
```
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt \
  -subj "/C=US/ST=State/L=City/O=MyCompany/OU=Security/CN=My Private Root CA"
```  
  
3) Generate server E256 private key
```
openssl ecparam -name $CURVE -genkey -noout -out server.key
```

4) Generate server certificate request
```
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=MyCompany/OU=IT/CN=localhost"
```  
  
5) Generate server certificate
```
openssl x509 -req -in server.csr \
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out server.crt -days 365 -sha256
```
  
  
6) Export to pkcs12 keystore (write `secret` when prompted for the password)
```
openssl pkcs12 -export -in server.crt -inkey server.key \
  -out keystore.p12 -name "server-alias" \
  -CAfile rootCA.crt -caname "root-alias" -chain
```
  
7) Copy file to the Keycloak keystore directory (assuming Keycloak realm name is `test`)
```
cp keystore.p12 $KEYCLOAK_HOME/data/test/keystore-e256.p12
```

8) In Keycloak admin console, create the `java-keystore` provider (in tab **Realm settings** -> **Keys** -> **Providers**) and give it priority 1:

* Name: java-keystore-es256
* Priority:1
* Algorithm: ES256
* Keystore: keystore-e256.p12
* keystore password: secret
* Keystore type: PKCS12
* Key alias: server-alias
* Key password: secret
* Key use: sig

9) May be also good to go to the particular OID4VCI client scope and select the **Credential signing algorithm** to `ES256`
