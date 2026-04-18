package org.wso2.custom.authenticator.futurae.common.web;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeClientException;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The HYPRWebUtils class contains all the general helper functions required by the HYPR Authenticator.
 */
public class FuturaeWebUtils {

    private static final Random rand = new SecureRandom();
    private static final String RFC_2822_PATTERN = "EEE, dd MMM yyyy HH:mm:ss Z";
    private static final DateTimeFormatter rfc2822Formatter = DateTimeFormatter.ofPattern(RFC_2822_PATTERN, Locale.US);

    /**
     * Private constructor.
     */
    private FuturaeWebUtils() {

    }

    /**
     * Send an HTTP Get request.
     *
     * @param apiKey   API token provided by Futurae.
     * @param requestURL The URL to which the GET request should be sent.
     * @return httpResponse         The response received from the HTTP call.
     * @throws IOException         Exception thrown when an error occurred during extracting the HTTP response content.
     * @throws FuturaeClientException Exception thrown when an error occurred with the HTTP client connection.
     */
    public static HttpResponse httpGet(String serviceId, String apiKey, URI requestURL) throws IOException, FuturaeClientException {

        HttpGet request = new HttpGet(requestURL);
        try {
            Map<String, String> generatedHeaders = requestHeaders(
                    request.getMethod(),
                    request.getURI().getHost(),
                    pathWithQuery(request.getURI()),
                    null,
                    serviceId,
                    apiKey);

            request.addHeader(HttpHeaders.AUTHORIZATION, generatedHeaders.get(HttpHeaders.AUTHORIZATION));
            request.addHeader("FT-Date", generatedHeaders.get("FT-Date"));

            CloseableHttpClient client = HTTPClientManager.getInstance().getHttpClient();
            try (CloseableHttpResponse response = client.execute(request)) {
                return toHttpResponse(response);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO : Fix error
            throw new FuturaeClientException("Failed to generate HMAC", "Failed to generate HMAC");
        }
    }

    /**
     * Send an HTTP POST request.
     *
     * @param apiKey    API token provided by HYPR.
     * @param requestURL  The URL to which the POST request should be sent.
     * @param requestBody A hashmap that includes the parameters to be sent through the request.
     * @return httpResponse         The response received from the HTTP call.
     * @throws IOException         Exception thrown when an error occurred during extracting the HTTP response content.
     * @throws FuturaeClientException Exception thrown when an error occurred with the HTTP client connection.
     */
    public static HttpResponse httpPost(String serviceId, String apiKey, URI requestURL, String requestBody)
            throws IOException, FuturaeClientException {

        HttpPost request = new HttpPost(requestURL);
        try {
            Map<String, String> generatedHeaders = requestHeaders(
                    request.getMethod(),
                    request.getURI().getHost(),
                    pathWithQuery(request.getURI()),
                    requestBody,
                    serviceId,
                    apiKey);

            request.addHeader(HttpHeaders.AUTHORIZATION, generatedHeaders.get(HttpHeaders.AUTHORIZATION));
            request.addHeader("FT-Date", generatedHeaders.get("FT-Date"));
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            request.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_JSON));

            CloseableHttpClient client = HTTPClientManager.getInstance().getHttpClient();
            try (CloseableHttpResponse response = client.execute(request)) {
                return toHttpResponse(response);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO : Fix error
            throw new FuturaeClientException("Failed to generate HMAC", "Failed to generate HMAC");
        }
    }

    private static HttpResponse toHttpResponse(final CloseableHttpResponse response) throws IOException {

        final HttpResponse result = new BasicHttpResponse(response.getStatusLine());
        if (response.getEntity() != null) {
            result.setEntity(new BufferedHttpEntity(response.getEntity()));
        }
        return result;
    }

    private static String pathWithQuery(URI uri) {
        String query = uri.getRawQuery();
        return (query != null && !query.isEmpty()) ? uri.getPath() + "?" + query : uri.getPath();
    }

    /**
     * Return HTTP Basic Authentication ("Authorization" and "FT-Date") headers.
     *
     * @param method request HTTP method
     * @param host   request host string (without port and without the "https://" prefix)
     * @param path   request path (including query params)
     * @param params request body parameters stringified
     * @param sid    Service ID
     * @param skey   Auth API key
     */
    private static Map<String, String> requestHeaders(String method, String host, String path, String params, String sid, String skey) throws InvalidKeyException, NoSuchAlgorithmException {
        params = (params == null) ? "" : params;
        String date = OffsetDateTime.now().format(rfc2822Formatter);
        String[] values = new String[]{date, method, host, path, params};

        StringBuilder data = new StringBuilder();
        for (String val : values) {
            data.append(val);
            data.append("\n");
        }

        String sig = bytesToHex(digest(data.toString(), skey));
        String auth = sid + ":" + sig;

        Map<String, String> headers = new HashMap<>();
        headers.put("FT-Date", date);
        headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8)));

        return headers;
    }

    private static byte[] digest(String content, String skey) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] contentBytes = content.getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HMACSHA256");
        SecretKeySpec macKey = new SecretKeySpec(skey.getBytes(StandardCharsets.UTF_8), "RAW");

        mac.init(macKey);

        return mac.doFinal(contentBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }

    /**
     * Generate  a random pin.
     *
     * @return A randomly generated pin.
     */
    private static int generateRandomPIN() {

        return 100000 + rand.nextInt(900000);
    }

    /**
     * Generate the hashcode.
     *
     * @param stringToHash The string on which the hash needs to be generated.
     * @return hashCode     The hash code  of the provided text.
     * @throws NoSuchAlgorithmException Exception thrown when an error occurred during getting the SHA-256 algorithm.
     */
    private static String doSha256(final String stringToHash) throws NoSuchAlgorithmException {

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(stringToHash.getBytes(StandardCharsets.UTF_8));
        final byte[] bytes = md.digest();
        final StringBuilder hexString = new StringBuilder();
        for (final byte aByte : bytes) {
            hexString.append(String.format("%02X", aByte));
        }
        return hexString.toString();
    }

    /**
     * Generate a random pin and get its hashcode.
     *
     * @return hashCode     The hash code of the generated random pin.
     * @throws NoSuchAlgorithmException Exception thrown when an error occurred during getting the SHA-256 algorithm.
     */
    public static String getRandomPinSha256() throws NoSuchAlgorithmException {

        return doSha256(String.valueOf(generateRandomPIN()));
    }


}
