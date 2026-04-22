package org.wso2.custom.authenticator.futurae.common.web;

import org.apache.commons.lang.ArrayUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeClientException;

import java.io.IOException;

import static java.util.Objects.isNull;

/**
 * Class to retrieve the HTTP Clients.
 */
public class HTTPClientManager {

    private static final int HTTP_CONNECTION_TIMEOUT = 3000;
    private static final int HTTP_READ_TIMEOUT = 3000;
    private static final int HTTP_CONNECTION_REQUEST_TIMEOUT = 3000;
    private static final int DEFAULT_MAX_CONNECTIONS = 20;
    private static volatile HTTPClientManager httpClientManagerInstance;
    private final CloseableHttpClient httpClient;

    /**
     * Creates a client manager.
     *
     * @throws FuturaeClientException Exception thrown when an error occurred when creating HTTP client.
     */
    private HTTPClientManager() throws FuturaeClientException {

        PoolingHttpClientConnectionManager connectionManager;
        try {
            connectionManager = createPoolingConnectionManager();
        } catch (IOException e) {
            throw handleServerException(FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_HTTP_CLIENT_CREATE, e);
        }

        RequestConfig config = createRequestConfig();
        httpClient = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .setConnectionManager(connectionManager).build();
    }

    /**
     * Returns an instance of the HTTPClientManager.
     *
     * @throws FuturaeClientException Exception thrown when an error occurred when creating HTTP client.
     */
    public static HTTPClientManager getInstance() throws FuturaeClientException {

        if (httpClientManagerInstance == null) {
            synchronized (HTTPClientManager.class) {
                if (httpClientManagerInstance == null) {
                    httpClientManagerInstance = new HTTPClientManager();
                }
            }
        }
        return httpClientManagerInstance;
    }

    /**
     * Get HTTP client.
     *
     * @return CloseableHttpClient instance.
     * @throws FuturaeClientException Exception thrown when an error occurred when getting HTTP client.
     */
    public CloseableHttpClient getHttpClient() throws FuturaeClientException {

        if (isNull(httpClient)) {
            throw handleServerException(
                    FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_HTTP_CLIENT_GET, null);
        }
        return httpClient;
    }

    private RequestConfig createRequestConfig() {

        return RequestConfig.custom()
                .setConnectTimeout(HTTP_CONNECTION_TIMEOUT)
                .setConnectionRequestTimeout(HTTP_CONNECTION_REQUEST_TIMEOUT)
                .setSocketTimeout(HTTP_READ_TIMEOUT)
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
    }

    private PoolingHttpClientConnectionManager createPoolingConnectionManager() throws IOException {

        PoolingHttpClientConnectionManager poolingHttpClientConnectionMgr = new PoolingHttpClientConnectionManager();
        // Increase max total connection to 20.
        poolingHttpClientConnectionMgr.setMaxTotal(DEFAULT_MAX_CONNECTIONS);
        // Increase default max connection per route to 20.
        poolingHttpClientConnectionMgr.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS);
        return poolingHttpClientConnectionMgr;
    }

    private static FuturaeClientException handleServerException(
            FuturaeAuthenticatorConstants.ErrorMessages error, Throwable throwable, String... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new FuturaeClientException(error.getMessage(), description, error.getCode(), throwable);
    }

}