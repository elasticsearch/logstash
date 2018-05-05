package org.logstash.common.clients;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.Header;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.*;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;

import javax.net.ssl.*;

/**
 * Easy-to-use HTTP client.
 */
public class HttpClient {
    public enum Protocol { HTTP, HTTPS }

    private final CloseableHttpClient httpClient;
    private final URL baseUrl;

    private HttpClient(CloseableHttpClient httpClient, URL baseUrl) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl;
    }

    /**
     * Performs an HTTP HEAD request
     *
     * @param relativePath  Relative path to resource, e.g. api/status
     * @throws RequestFailedException
     * @throws IOException
     */
    public void head(String relativePath) throws RequestFailedException, IOException {
        head(relativePath, null);
    }

    /**
     * Performs an HTTP HEAD request
     *
     * @param relativePath  Relative path to resource, e.g. api/status
     * @param headers       Headers to include with request
     * @throws RequestFailedException
     * @throws IOException
     */
    public void head(String relativePath, Map<String, String> headers) throws RequestFailedException, IOException {
        String url = makeUrlFrom(relativePath);
        HttpHead request = new HttpHead(url);

        if (headers != null) {
            headers.forEach(request::addHeader);
        }

        CloseableHttpResponse response = null;

        try {
            response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new RequestFailedException("HEAD", url , response.getStatusLine().getReasonPhrase());
            }

        } catch (IOException e) {
            throw new RequestFailedException("HEAD", url ,e);
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    /**
     * Performs an HTTP GET request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/export
     * @return Response body
     * @throws RequestFailedException
     */
    public String get(String relativePath) throws RequestFailedException, IOException {
        return get(relativePath, null);
    }

    /**
     * Performs an HTTP GET request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/export
     * @param headers       Headers to include with request
     * @return Response body
     * @throws RequestFailedException
     * @throws IOException
     */
    public String get(String relativePath, Map<String, String> headers) throws RequestFailedException, IOException {
        String url = makeUrlFrom(relativePath);
        HttpGet request = new HttpGet(url);

        if (headers != null) {
            headers.forEach(request::addHeader);
        }

        CloseableHttpResponse response = null;

        try {
            response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new RequestFailedException("HEAD", url , response.getStatusLine().getReasonPhrase());
            }

            OutputStream responseBody = new ByteArrayOutputStream();
            response
                .getEntity()
                .writeTo(responseBody);
            return ((ByteArrayOutputStream) responseBody).toString("UTF-8");

        } catch (IOException e) {
            throw new RequestFailedException("GET", url, e);
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    /**
     * Performs an HTTP POST request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/import
     * @param requestBody   Body of request
     * @return Response body
     * @throws RequestFailedException
     * @throws IOException
     */
    public String post(String relativePath, String requestBody) throws RequestFailedException, IOException {
        return post(relativePath, requestBody, null);
    }

    /**
     * Performs an HTTP POST request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/import
     * @param requestBody   Body of request
     * @param headers       Headers to include with request
     * @return Response body
     * @throws RequestFailedException
     * @throws IOException
     */
    public String post(String relativePath, String requestBody, Map<String, String> headers) throws RequestFailedException, IOException {

        String url = makeUrlFrom(relativePath);

        HttpPost request = new HttpPost(url);
        request.setEntity(new StringEntity(requestBody));

        if (headers != null) {
            headers.forEach(request::addHeader);
        }

        CloseableHttpResponse response = null;

        try {
            response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new RequestFailedException("HEAD", url , response.getStatusLine().getReasonPhrase());
            }

            OutputStream responseBody = new ByteArrayOutputStream();
            response
                    .getEntity()
                    .writeTo(responseBody);
            return ((ByteArrayOutputStream) responseBody).toString("UTF-8");
        } catch (IOException e) {
            throw new RequestFailedException("POST", url, e);
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    /**
     * Performs an HTTP PUT request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/import
     * @param requestBody   Body of request
     * @return Response body
     * @throws RequestFailedException
     * @throws IOException
     */
    public String put(String relativePath, String requestBody) throws RequestFailedException, IOException {
        return put(relativePath, requestBody, null);
    }

    /**
     * Performs an HTTP PUT request
     *
     * @param relativePath  Relative path to resource, e.g. api/kibana/dashboards/import
     * @param requestBody   Body of request
     * @param headers       Headers to include with request
     * @return Response body
     * @throws RequestFailedException
     * @throws IOException
     */
    public String put(String relativePath, String requestBody, Map<String, String> headers) throws RequestFailedException, IOException {

        String url = makeUrlFrom(relativePath);

        HttpPut request = new HttpPut(url);
        request.setEntity(new StringEntity(requestBody));

        if (headers != null) {
            headers.forEach(request::addHeader);
        }

        CloseableHttpResponse response = null;

        try {
            response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new RequestFailedException("HEAD", url , response.getStatusLine().getReasonPhrase());
            }

            OutputStream responseBody = new ByteArrayOutputStream();
            response
                    .getEntity()
                    .writeTo(responseBody);
            return ((ByteArrayOutputStream) responseBody).toString("UTF-8");
        } catch (IOException e) {
            throw new RequestFailedException("PUT", url, e);
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    /**
     * Performs an HTTP DELETE request
     *
     * @param relativePath  Relative path to resource, e.g. api/status
     * @throws RequestFailedException
     * @throws IOException
     */
    public void delete(String relativePath) throws RequestFailedException, IOException {
        delete(relativePath, null);
    }

    /**
     * Performs an HTTP DELETE request
     *
     * @param relativePath  Relative path to resource, e.g. api/status
     * @param headers       Headers to include with request
     * @throws RequestFailedException
     * @throws IOException
     */
    public void delete(String relativePath, Map<String, String> headers) throws RequestFailedException, IOException {
        String url = makeUrlFrom(relativePath);
        HttpDelete request = new HttpDelete(url);

        if (headers != null) {
            headers.forEach(request::addHeader);
        }

        CloseableHttpResponse response = null;

        try {
            response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() >= 400) {
                throw new RequestFailedException("HEAD", url , response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            throw new RequestFailedException("DELETE", url ,e);
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    private String makeUrlFrom(String relativePath) {
        return this.baseUrl.toString().replaceFirst("/$", "")
                + '/'
                + relativePath.replaceFirst("^/", "");
    }

    /**
     * Build an instance of the HTTP client with default configuration options.
     *
     * @return HTTP client instance
     * @throws OptionsBuilderException
     */
    public static HttpClient build() throws OptionsBuilderException {
        return new OptionsBuilder().build();
    }

    /**
     * Start building an instance of the HTTP client.
     *
     * @return An {@see OptionsBuilder} instance to allow configuration of the HTTP client before building it.
     */
    public static OptionsBuilder builder() {
        return new OptionsBuilder();
    }

    /**
     * Builder pattern obj
     */
    public static class OptionsBuilder {

        private Protocol protocol;
        private String hostname;
        private int port;
        private String basePath;

        private String basicAuthUsername;
        private String basicAuthPassword;

        private X509Certificate sslCaCertificate;
        private X509Certificate sslClientCertificate;
        private RSAPrivateKey sslClientPrivateKey;
        private boolean sslVerifyServerHostname;
        private boolean sslVerifyServerCredentials;

        private OptionsBuilder() {
            this.protocol = Protocol.HTTP;
            this.hostname = "localhost";
            this.port = 80;
            this.basePath = "/";
            this.sslVerifyServerHostname = true;
            this.sslVerifyServerCredentials = true;
        }

        /**
         * Set the HTTP server's protocol (HTTP or HTTPS) that should be used by the HTTP client
         * when making requests. Defaults to HTTP.
         *
         * @param protocol Server protocol, HTTP or HTTPS
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder protocol(Protocol protocol) {
            this.protocol = protocol;
            return this;
        }

        /**
         * Set the HTTP server's hostname that should be used by the HTTP client when making requests.
         * Defaults to localhost.
         *
         * @param hostname Server hostname
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder hostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        /**
         * Set the HTTP server's port that should be used by the HTTP client when making requests. Defaults
         * to 80.
         *
         * @param port Server port
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder port(int port) {
            this.port = port;
            return this;
        }

        /**
         * Set the HTTP server's base path that should be used by the HTTP client when making requests. Defaults
         * to /.
         *
         * @param basePath Server basePath
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder basePath(String basePath) {
            this.basePath = basePath;
            return this;
        }

        /**
         * Set the HTTP server's basic authentication credentials that should be used by the HTTP client when
         * making requests. By default, no basic authentication is used.
         *
         * @param username Basic authentication username
         * @param password Basic authentication password
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder basicAuth(String username, String password) {
            this.basicAuthUsername = username;
            this.basicAuthPassword = password;

            return this;
        }

        /**
         * Set the Certificate Authority's certificate that the HTTP client should use for validating the
         * server's SSL/TLS certificate. By default the certificate authority certificates provided by
         * the system are used.
         *
         * @param caCertificatePath Path to Certificate Authority certificate file
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         * @throws OptionsBuilderException
         */
        public OptionsBuilder sslCaCertificate(String caCertificatePath) throws OptionsBuilderException {
            try {
                this.sslCaCertificate = getCertificate(caCertificatePath);
            } catch (Exception e) {
                throw new OptionsBuilderException("Could not set SSL CA certificate", e);
            }
            return this;
        }

        /**
         * Set the client's certificate the HTTP client should present to the server, should the server ask for it during
         * the ClientKeyExchange step. By default no client certificate is presented to the server.
         *
         * @param clientCertificatePath Path to client certificate file
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         * @throws OptionsBuilderException
         */
        public OptionsBuilder sslClientCertificate(String clientCertificatePath) throws OptionsBuilderException {
            try {
                this.sslClientCertificate = getCertificate(clientCertificatePath);
            } catch (Exception e) {
                throw new OptionsBuilderException("Could not set SSL client certificate", e);
            }
            return this;
        }

        /**
         * Set the client's private key the HTTP client should use during the (optional) ClientKeyExchange step. By
         * default no client private key is used.
         *
         * @param clientPrivateKeyPath Path to client private key file
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         * @throws OptionsBuilderException
         */
        public OptionsBuilder sslClientPrivateKey(String clientPrivateKeyPath) throws OptionsBuilderException {
            try {
                this.sslClientPrivateKey = getPrivateKey(clientPrivateKeyPath);
            } catch (OptionsBuilderException e) {
                throw e;
            } catch (Exception e) {
                throw new OptionsBuilderException("Could not set SSL client private key", e);
            }
            return this;
        }

        /**
         * Tell the HTTP client not to verify the server's hostname against the server's certificate.
         *
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder sslNoVerifyServerHostname() {
            this.sslVerifyServerHostname = false;
            return this;
        }

        /**
         * Tell the HTTP client not to verify the server's certificate against a Certificate Authority.
         *
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder sslNoVerifyServerCredentials() {
            this.sslVerifyServerCredentials = false;
            return this;
        }

        /**
         * Tell the HTTP client not to perform any SSL verification checks.
         *
         * @return Same {@see OptionsBuilder } instance to continue configuring HTTP client
         */
        public OptionsBuilder sslNoVerify() {
            return this.sslNoVerifyServerHostname()
                    .sslNoVerifyServerCredentials();
        }

        /**
         * Finish building configuration for the HTTP client.
         *
         * @return Instance of the HTTP client with configuration options provided.
         * @throws OptionsBuilderException
         */
        public HttpClient build() throws OptionsBuilderException {

            URL baseUrl;
            try {
                baseUrl = new URL(this.protocol.name().toLowerCase(), this.hostname, this.port, this.basePath);
            } catch (MalformedURLException e) {
                throw new OptionsBuilderException("Unable to create base URL", e);
            }

            if (!usesSsl(baseUrl) && !usesBasicAuth()) {
                CloseableHttpClient httpClient = HttpClients.createDefault();
                return new HttpClient(httpClient, baseUrl);
            }

            HttpClientBuilder httpClientBuilder = HttpClients.custom();

            if (usesSsl(baseUrl)) {
                TrustManager[] trustManagers;
                if (this.sslVerifyServerCredentials) {
                    if (this.sslCaCertificate == null) {
                        throw new OptionsBuilderException("Certificate authority not provided. "
                                + "Please provide the certificate authority using the sslCaCertificate method.");
                    }

                    try {
                        KeyStore keystore = getKeyStore();
                        keystore.setCertificateEntry("caCertificate", this.sslCaCertificate);

                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        trustManagerFactory.init(keystore);

                        trustManagers = trustManagerFactory.getTrustManagers();
                    } catch (Exception e) {
                        throw new OptionsBuilderException("Unable to use provided certificate authority.", e);
                    }
                } else {
                    trustManagers = new TrustManager[] { getAnyTrustManager() };
                }

                KeyManager[] keyManagers = null;
                if ((this.sslClientCertificate != null) && (this.sslClientPrivateKey != null)) {
                    KeyStore keystore = getKeyStore();

                    try {
                        keystore.setKeyEntry("clientPrivateKey", this.sslClientPrivateKey, "".toCharArray(), new Certificate[]{this.sslClientCertificate});

                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                        keyManagerFactory.init(keystore, "".toCharArray());

                        keyManagers = keyManagerFactory.getKeyManagers();
                    } catch (Exception e) {
                        throw new OptionsBuilderException("Unable to use provided client certificate and/or client private key", e);
                    }
                }

                try {
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(keyManagers, trustManagers, null);

                    SSLConnectionSocketFactory sslSocketFactory;
                    if (this.sslVerifyServerHostname) {
                        sslSocketFactory = new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER);
                    } else {
                        sslSocketFactory = new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                    }

                    httpClientBuilder.setSSLSocketFactory(sslSocketFactory);
                } catch (Exception e) {
                    throw new OptionsBuilderException("Unable to configure HTTP client with SSL/TLS", e);
                }
            }

            if (usesBasicAuth()) {
                String credentials = this.basicAuthUsername + ":" + this.basicAuthPassword;
                String encodedCredentials = new String(Base64.getEncoder().encode(credentials.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

                List<Header> headerList = Collections.singletonList(new BasicHeader("Authorization", "Basic " + encodedCredentials));
                httpClientBuilder.setDefaultHeaders(headerList);
            }

            return new HttpClient(httpClientBuilder.build(), baseUrl);
        }

        private boolean usesBasicAuth() {
            return (this.basicAuthUsername != null) && (this.basicAuthPassword != null);
        }

        private boolean usesSsl(URL baseUrl) {
            return baseUrl.getProtocol().equals("https");
        }

        private static X509Certificate getCertificate(String certificateFilePath) throws CertificateException, IOException {
            FileInputStream fis = new FileInputStream(certificateFilePath);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate;

            try {
                certificate = (X509Certificate) cf.generateCertificate(fis);
            } finally {
                fis.close();
            }

            return certificate;
        }

        private static RSAPrivateKey getPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, OptionsBuilderException {
            String privateKeyFileContents = new String(Files.readAllBytes(Paths.get(privateKeyPath)));

            final Pattern KEY_EXTRACTION_REGEXP = Pattern.compile(".*-----BEGIN (\\S+ )?PRIVATE KEY-----\n(.*)-----END (\\S+ )?PRIVATE KEY.*$", Pattern.DOTALL);
            Matcher matcher = KEY_EXTRACTION_REGEXP.matcher(privateKeyFileContents);

            final String obeMessage = "Could not parse private key file at " + privateKeyPath;

            if (!matcher.matches()) {
                throw new OptionsBuilderException(obeMessage);
            }

            String keyContentsBase64Encoded = matcher.group(2);
            if (keyContentsBase64Encoded == null) {
                throw new OptionsBuilderException(obeMessage);
            }

            byte[] keyContents;
            try {
                keyContents = Base64.getDecoder().decode(keyContentsBase64Encoded.replaceAll("\n", ""));
            } catch (Exception e) {
                throw new OptionsBuilderException(obeMessage, e);
            }

            KeySpec spec = new PKCS8EncodedKeySpec(keyContents);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
        }

        private static KeyStore getKeyStore() throws OptionsBuilderException {
            KeyStore keystore;
            try {
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(null, null);
            } catch (Exception e) {
                throw new OptionsBuilderException("Unable to create keystore", e);
            }
            return keystore;
        }

        private static X509TrustManager getAnyTrustManager() {
            return new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {

                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {

                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        }

    }

    /**
     * Exception thrown when there is an error while configuring an HTTP client instance
     */
    public static class OptionsBuilderException extends Exception {
        public OptionsBuilderException(String errorMessage, Throwable cause) {
            super(errorMessage, cause);
        }

        public OptionsBuilderException(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * Exception thrown when a request made by this client to the HTTP resource fails
     */
    public static class RequestFailedException extends Exception {
        RequestFailedException(String method, String url, Throwable cause) {
            super(makeMessage(method, url, null), cause);
        }

        RequestFailedException(String method, String url, String reason) {
            super(makeMessage(method, url, reason));
        }

        private static String makeMessage(String method, String url, String reason) {
            String message = "Could not make " + method + " " + url + " request";
            if (reason != null) {
                message += "; reason: " + reason;
            }
            return message;
        }
    }
}
