package org.wso2.custom.authenticator.futurae.rest.v1.core;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeAuthnFailedException;
import org.wso2.custom.authenticator.futurae.common.model.AuthStateResponse;
import org.wso2.custom.authenticator.futurae.common.web.FuturaeAuthenticationAPIClient;
import org.wso2.custom.authenticator.futurae.rest.common.error.APIError;
import org.wso2.custom.authenticator.futurae.rest.common.error.ErrorResponse;
import org.wso2.custom.authenticator.futurae.rest.v1.StatusResponse;


import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

//TODO: Validate try catch
/**
 * The ServerFuturaeAuthenticatorService class contains all the functional tasks handled by the Futurae REST API,
 * such as getting the authentication status of a user provided the session key.
 */
public class ServerFuturaeAuthenticatorService {

    /**
     * Get the authentication status of the user with the given session key via an API call to the Futurae server.
     *
     * @param sessionKey The session key assigned for the user by the framework.
     * @return StatusResponse
     */
    public StatusResponse getAuthenticationStatus(String sessionKey) {

        try {
            // Get the authentication context based on the session key.
            AuthenticationContext authenticationContext = getAuthenticationContext(sessionKey);

            // Extract Futurae configurations.
            Map<String, String> futuraeConfigurations = getFuturaeConfigurations(authenticationContext);

            // Extract Futurae authentication properties.
            Map<String, String> futuraeAuthenticationProperties = getFuturaeAuthenticationProperties(authenticationContext);

            // If the authentication status property has assigned with one of the terminating status
            // (i.e. "COMPLETED", "FAILED", "CANCELED"), avoid making API call to the Futurae server.
            String previousState = futuraeAuthenticationProperties.get(FuturaeAuthenticatorConstants.AUTH_STATUS);
            if (FuturaeAuthenticatorConstants.TERMINATING_STATUSES.contains(previousState)) {
                StatusResponse statusResponse = new StatusResponse();
                statusResponse.setStatus(StatusResponse.StatusEnum.fromValue(previousState));
                statusResponse.setSessionKey(sessionKey);
                return statusResponse;
            }

            // Make an API call to get the authentication status from the Futurae server.
            AuthStateResponse authStateResponse = FuturaeAuthenticationAPIClient.getAuthenticationStatus(
                    futuraeConfigurations.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName()),
                    futuraeConfigurations.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName()),
                    futuraeConfigurations.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName()),
                    futuraeAuthenticationProperties.get(FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID),
                    authenticationContext.getLastAuthenticatedUser().getUserName());

            FuturaeAuthenticatorConstants.AuthenticationStatus resolvedStatus =
                    resolveAuthenticationStatus(authStateResponse.getResult());

            // Store the mapped internal status in the authentication context.
            authenticationContext.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS, resolvedStatus.getName());

            // Return the state as a REST API response.
            StatusResponse statusResponse = new StatusResponse();
            statusResponse.setStatus(StatusResponse.StatusEnum.fromValue(resolvedStatus.getName()));
            statusResponse.setSessionKey(sessionKey);

            return statusResponse;

        } catch (FuturaeAuthnFailedException e) {
            if (FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES.getCode()
                    .equals(e.getErrorCode())) {
                // Handle invalid request id.
                throw handleInvalidInput(FuturaeAuthenticatorConstants
                        .ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES);
            } else if (FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS.getCode()
                    .equals(e.getErrorCode())) {
                // Handle invalid or expired api token.
                throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                        FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS);
            }
        }

        throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_GENERAL);
    }

    /**
     * Get the authentication context based on the session key.
     *
     * @param sessionKey The session key assigned for the user by the framework.
     */
    private AuthenticationContext getAuthenticationContext(String sessionKey) {

        AuthenticationContext authenticationContext = FrameworkUtils.getAuthenticationContextFromCache(sessionKey);
        if (authenticationContext == null) {
            throw handleInvalidInput(FuturaeAuthenticatorConstants.ErrorMessages.CLIENT_ERROR_INVALID_SESSION_KEY);
        }
        return authenticationContext;
    }

    /**
     * Extract the Futurae authenticator configurations from the context.
     *
     * @param sessionContext The authentication context for the given session key.
     */
    private Map<String, String> getFuturaeConfigurations(AuthenticationContext sessionContext) {

        Map<String, String> authenticatorProperties = sessionContext.getAuthenticatorProperties();

        if (!(authenticatorProperties.containsKey(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName()) &&
                authenticatorProperties.containsKey(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName()) &&
                authenticatorProperties.containsKey(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName())
        )) {
            throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                    FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS);
        }

        String serviceHostname = authenticatorProperties.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceId = authenticatorProperties.get(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = authenticatorProperties.get(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

        if (StringUtils.isBlank(serviceHostname) || StringUtils.isBlank(serviceId) || StringUtils.isBlank(authApiKey)) {
            throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                    FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS);
        }

        Map<String, String> futuraeConfigurations = new HashMap<>();
        futuraeConfigurations.put(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName(), serviceHostname);
        futuraeConfigurations.put(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName(), serviceId);
        futuraeConfigurations.put(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName(), authApiKey);

        return futuraeConfigurations;
    }

    /**
     * Extract the user authentication properties such as authentication status and request ID from the context.
     *
     * @param authenticationContext The authentication context for the given session key.
     */
    private Map<String, String> getFuturaeAuthenticationProperties(AuthenticationContext authenticationContext) {

        if (authenticationContext.getProperty(FuturaeAuthenticatorConstants.AUTH_STATUS) == null ||
                authenticationContext.getProperty(FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID) == null) {
            throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                    FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES);
        }

        String authStatus = String.valueOf(authenticationContext.getProperty(
                FuturaeAuthenticatorConstants.AUTH_STATUS));
        String futuraeSessionId = String.valueOf(authenticationContext.getProperty(
                FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID));

        if (StringUtils.isBlank(authStatus) || StringUtils.isBlank(futuraeSessionId)) {
            throw handleError(Response.Status.INTERNAL_SERVER_ERROR,
                    FuturaeAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES);
        }

        Map<String, String> futuraeAuthenticationProperties = new HashMap<>();
        futuraeAuthenticationProperties.put(FuturaeAuthenticatorConstants.AUTH_STATUS, authStatus);
        futuraeAuthenticationProperties.put(FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID, futuraeSessionId);

        return futuraeAuthenticationProperties;
    }

    /**
     * Maps the Futurae API result value to the internal AuthenticationStatus.
     *
     * Futurae result values:
     *   "allow"   → COMPLETED  (authentication succeeded)
     *   "deny"    → FAILED     (authentication failed or denied)
     *   "waiting" → PENDING    (authentication still in progress)
     *
     * @param futuraeResult The result string returned by the Futurae auth status API.
     * @return The mapped AuthenticationStatus, or FAILED for any unrecognised value.
     */
    private FuturaeAuthenticatorConstants.AuthenticationStatus resolveAuthenticationStatus(String futuraeResult) {

        if (futuraeResult == null) {
            return FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED;
        }
        return switch (futuraeResult) {
            case "allow" -> FuturaeAuthenticatorConstants.AuthenticationStatus.COMPLETED;
            case "waiting" -> FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING;
            default -> FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED;
        };
    }

    private APIError handleInvalidInput(FuturaeAuthenticatorConstants.ErrorMessages errorEnum, String... data) {

        return handleError(Response.Status.BAD_REQUEST, errorEnum);
    }

    private APIError handleError(Response.Status status, FuturaeAuthenticatorConstants.ErrorMessages error) {

        return new APIError(status, getErrorBuilder(error).build());
    }

    private ErrorResponse.Builder getErrorBuilder(FuturaeAuthenticatorConstants.ErrorMessages errorEnum) {

        return new ErrorResponse.Builder().withCode(errorEnum.getCode()).withMessage(errorEnum.getMessage())
                .withDescription(errorEnum.getDescription());
    }
}
