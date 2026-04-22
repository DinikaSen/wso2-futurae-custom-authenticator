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
import java.util.Map;

import static org.wso2.custom.authenticator.futurae.common.util.FuturaeUtils.getFuturaeAuthnFailedException;

/**
 * The FuturaeAuthenticationAPIClient class contains all the functions related to handling the API calls to Futurae.
 **/
public class FuturaeAuthenticationAPIClient {

    /**
     * Call the Futurae server API to retrieve the available authentication options for the user.
     *
     * @param futuraeConfig    Map containing serviceHostname, serviceId and authApiKey.
     * @param username         The username provided by the user.
     * @param futuraeCredential Optional trusted device token; pass blank string if not applicable.
     * @return PreAuthResponse
     * @throws FuturaeAuthnFailedException
     */
    public static PreAuthResponse getAuthenticationOptions(Map<String, String> futuraeConfig,
                                                           String username, String futuraeCredential)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .PREAUTH_RETRIEVAL_FAILURE);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .PREAUTH_RETRIEVAL_FAILURE, e);
        } catch (FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_HTTP_CLIENT_CREATE, e);
        }
    }

    public static AuthResponse sendAuthRequest(Map<String, String> futuraeConfig,
                                               String username, String authFactor) throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    public static AuthStateResponse getAuthenticationStatus(
            Map<String, String> futuraeConfig, String futuraeSessionId, String username)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_SESSION);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Look up a user by username via GET /srv/auth/v1/users.
     *
     * @param futuraeConfig Map containing serviceHostname, serviceId and authApiKey.
     * @param username      The username to search for.
     * @return UserSearchResponse if the user exists, or {@code null} if the user is not found (400).
     * @throws FuturaeAuthnFailedException on 401, network, or unexpected errors.
     */
    public static UserSearchResponse lookupUserByUsername(Map<String, String> futuraeConfig, String username)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Unenroll (deactivate) a device for a user via POST /srv/auth/v1/user/unenroll.
     *
     * @param futuraeConfig   Map containing serviceHostname, serviceId and authApiKey.
     * @param unenrollRequest The unenroll request specifying the user and device to unenroll.
     * @return UnenrollDeviceResponse containing the result.
     * @throws FuturaeAuthnFailedException on 400, 401, or unexpected errors.
     */
    public static UnenrollDeviceResponse unenrollDevice(Map<String, String> futuraeConfig,
                                                        UnenrollDeviceRequest unenrollRequest)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Enroll a device via POST /srv/auth/v1/user/enroll.
     *
     * @param futuraeConfig Map containing serviceHostname, serviceId and authApiKey.
     * @param enrollRequest The enroll request built with {@link EnrollRequest#forExistingUser(String)}
     *                      or {@link EnrollRequest#forNewUser()}.
     * @return EnrollResponse containing the activation code, QR code URL, and enrollment metadata.
     * @throws FuturaeAuthnFailedException on 400, 401, or unexpected errors.
     */
    public static EnrollResponse enrollDevice(Map<String, String> futuraeConfig, EnrollRequest enrollRequest)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

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
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    /**
     * Retrieve the status and enrolled devices of a Futurae user via GET /srv/auth/v1/users/{id}.
     *
     * @param futuraeConfig Map containing serviceHostname, serviceId and authApiKey.
     * @param futuraeUserId The Futurae user ID (UUID) of the user to look up.
     * @return {@link UserInfoResponse} containing the user's status, allowed factors, and devices.
     * @throws FuturaeAuthnFailedException on 400 (bad request), 401 (invalid credentials), or unexpected errors.
     */
    public static UserInfoResponse getUserInfo(Map<String, String> futuraeConfig, String futuraeUserId)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_USER_PATH + "/" + futuraeUserId);

            HttpResponse response = FuturaeWebUtils.httpGet(serviceId, authApiKey, uriBuilder.build());

            Gson gson = new GsonBuilder().create();

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return gson.fromJson(jsonString, UserInfoResponse.class);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_TOKEN_INVALID);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }

    public static EnrollStatusResponse getEnrollmentStatus(Map<String, String> futuraeConfig,
                                                           EnrollStatusRequest enrollStatusRequest)
            throws FuturaeAuthnFailedException {

        String serviceHostname = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = futuraeConfig.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

        try {
            URIBuilder uriBuilder = new URIBuilder()
                    .setScheme("https")
                    .setHost(serviceHostname)
                    .setPath(FuturaeAuthenticatorConstants.FUTURAE_DEVICE_ENROLL_STATUS_PATH);

            Gson gson = new GsonBuilder().create();
            String jsonRequestBody = gson.toJson(enrollStatusRequest);

            HttpResponse response = FuturaeWebUtils.httpPost(serviceId, authApiKey, uriBuilder.build(), jsonRequestBody);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                return gson.fromJson(jsonString, EnrollStatusResponse.class);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_TOKEN_INVALID);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .API_INVALID_REQUEST);
            } else {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                        .SERVER_ERROR_GENERAL);
            }
        } catch (URISyntaxException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.API_INVALID_SERVICE_URL, e);
        } catch (IOException | FuturaeClientException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .SERVER_ERROR_GENERAL, e);
        }
    }
}