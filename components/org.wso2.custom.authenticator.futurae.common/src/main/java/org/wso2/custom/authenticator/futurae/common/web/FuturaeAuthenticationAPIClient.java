package org.wso2.custom.authenticator.futurae.common.web;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeAuthnFailedException;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeClientException;
import org.wso2.custom.authenticator.futurae.common.model.*;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.wso2.custom.authenticator.futurae.common.util.FuturaeUtils.getFuturaeAuthnFailedException;

/**
 * The FuturaeAuthenticationAPIClient class contains all the functions related to handling the API calls to Futurae.
 **/
public class FuturaeAuthenticationAPIClient {

    /**
     * Call the Futurae server API to retrieve the available authentication options for the user.
     *
     * @param serviceHostname
     * @param serviceId
     * @param username        The username provided by the user.
     * @return response         A HTTPResponse object.
     * @throws FuturaeAuthnFailedException Exception throws when there is an error occurred when retrieving the
     *                                     registered devices via the api call
     */
    public static PreAuthResponse getAuthenticationOptions(String serviceHostname, String serviceId, String authApiKey,
                                                           String username, String futuraeCredential)
            throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_PRE_AUTH_PATH);

            PreAuthRequest preAuthRequest;
            if (StringUtils.isNotBlank(futuraeCredential)) {
                preAuthRequest = PreAuthRequest.byUsername(username).withTrustedDeviceToken(futuraeCredential);
            } else {
                preAuthRequest = PreAuthRequest.byUsername(username);
            }

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(preAuthRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                return gson.fromJson(jsonString, PreAuthResponse.class);

            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_INVALID_REQUEST_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .AUTHENTICATION_FAILED_RETRIEVING_PRE_AUTH_FAILURE);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .AUTHENTICATION_FAILED_RETRIEVING_PRE_AUTH_FAILURE, e);
        } catch (FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_CREATING_HTTP_CLIENT, e);
        }
    }

    public static AuthResponse sendAuthRequest(String serviceHostname, String serviceId, String authApiKey,
                                               String username, String authFactor) throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_AUTH_PATH);

            AuthRequest authRequest = AuthRequest.byUsername(username, authFactor);

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(authRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                return gson.fromJson(jsonString, AuthResponse.class);

            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_INVALID_REQUEST_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    public static AuthStateResponse getAuthenticationStatus(
            String serviceHostname, String serviceId, String authApiKey, String futuraeSessionId, String username)
            throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_AUTH_STATE_PATH);

            AuthStateRequest authStateRequest = new AuthStateRequest(futuraeSessionId).withUsername(username);

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(authStateRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                return gson.fromJson(jsonString, AuthStateResponse.class);

            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_INVALID_SESSION_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }

    }

    /**
     * Look up a user by username via GET /srv/auth/v1/users.
     *
     * @param serviceHostname The Futurae service hostname.
     * @param serviceId       The Futurae service ID.
     * @param authApiKey      The Futurae auth API key.
     * @param username        The username to search for.
     * @return UserSearchResponse if the user exists, or {@code null} if the user is not found (400).
     * @throws FuturaeAuthnFailedException on 401, network, or unexpected errors.
     */
    public static UserSearchResponse lookupUserByUsername(
            String serviceHostname, String serviceId, String authApiKey, String username)
            throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_USER_PATH)
                    .addParameter("username", username);

            HttpResponse response = FuturaeWebUtils.httpGet(serviceId, authApiKey, uriBuilder.build());

            Gson gson = new GsonBuilder().create();

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return gson.fromJson(jsonString, UserSearchResponse.class);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                return null;
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Unenroll (deactivate) a device for a user via POST /srv/auth/v1/user/unenroll.
     * If the device is the user's only enrolled device, Futurae authentication is automatically
     * disabled for that user.
     *
     * @param serviceHostname The Futurae service hostname.
     * @param serviceId       The Futurae service ID (used for HMAC auth).
     * @param authApiKey      The Futurae auth API key.
     * @param unenrollRequest The unenroll request specifying the user and device to unenroll.
     * @return UnenrollDeviceResponse containing the result ("success" or "success_2fa_disabled").
     * @throws FuturaeAuthnFailedException on 400 (invalid request), 401 (bad token), or unexpected errors.
     */
    public static UnenrollDeviceResponse unenrollDevice(String serviceHostname, String serviceId,
                                                        String authApiKey, UnenrollDeviceRequest unenrollRequest)
            throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_DEVICE_UNENROLL_PATH);

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(unenrollRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return gson.fromJson(jsonString, UnenrollDeviceResponse.class);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_INVALID_REQUEST_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Enroll a new device for an existing Futurae user via POST /srv/auth/v1/user/enroll.
     * Returns an activation code and QR code for the user to scan with the Futurae mobile app.
     *
     * @param serviceHostname The Futurae service hostname.
     * @param serviceId       The Futurae service ID (used for HMAC auth).
     * @param authApiKey      The Futurae auth API key.
     * @param enrollRequest   The enroll request built with {@link EnrollRequest#forExistingUser(String)}.
     * @return EnrollResponse containing the activation code, QR code URL, and enrollment metadata.
     * @throws FuturaeAuthnFailedException on 400 (invalid request), 401 (bad token), or unexpected errors.
     */
    public static EnrollResponse enrollDevice(String serviceHostname, String serviceId,
                                              String authApiKey, EnrollRequest enrollRequest)
            throws FuturaeAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_DEVICE_ENROLL_PATH);

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(enrollRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return gson.fromJson(jsonString, EnrollResponse.class);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .FUTURAE_ENDPOINT_INVALID_REQUEST_FAILURE);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }
}
