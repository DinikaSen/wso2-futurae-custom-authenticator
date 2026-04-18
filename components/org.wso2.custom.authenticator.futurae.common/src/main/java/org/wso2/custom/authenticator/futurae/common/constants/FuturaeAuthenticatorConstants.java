package org.wso2.custom.authenticator.futurae.common.constants;

import java.util.Arrays;
import java.util.List;

/**
 * Includes the Futurae authentication and registration related constants.
 */
public class FuturaeAuthenticatorConstants {

    // Authenticator related constants
    public static final String AUTHENTICATOR_NAME = "FuturaeAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Futurae";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String TENANT_DOMAIN = "tenantDomain";
    public static final String USERNAME = "username";
    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";
    public static final String AUTH_TYPE = "authType";
    public static final String AUTH_TYPE_FUTURAE = "futurae";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String FUTURAE_DEVICE_ID_CLAIM = "http://wso2.org/claims/futuraeDeviceId";
    public static final String FUTURAE_USER_ID_CLAIM = "http://wso2.org/claims/futuraeUserId";
    public static final String USER_ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String AUTH_STATUS = "authStatus";
    public static final String FUTURAE_SESSION_ID = "futuraeSessionId";
    public static final String IS_INITIAL_FEDERATED_USER_ATTEMPT = "isInitialFederationAttempt";

    public static final String CORRELATION_ID_KEY = "Correlation-ID";

    //Page paths
    public static final String FUTURAE_LOGIN_PAGE = "/authenticationendpoint/futuraelogin.jsp";
    public static final String ENROLLMENT_QR_URL_PARAM = "enrollmentQrUrl";

    // Authentication API paths
    public static final String FUTURAE_PRE_AUTH_PATH = "/srv/auth/v1/user/preauth";
    public static final String FUTURAE_AUTH_PATH = "/srv/auth/v1/user/auth";
    public static final String FUTURAE_AUTH_STATE_PATH = "/srv/auth/v1/user/auth/status";
    public static final String FUTURAE_DEVICE_ENROLL_PATH = "/srv/auth/v1/user/enroll";
    public static final String FUTURAE_DEVICE_UNENROLL_PATH = "/srv/auth/v1/user/unenroll";
    public static final String FUTURAE_USER_PATH = "/srv/auth/v1/users";


    // Futurae supported factors
    public static final String APPROVE = "approve";
    public static final String UNENROLL_SUCCESS = "success";
    public static final String UNENROLL_SUCCESS_2FA = "success_2fa_disabled";

    // Authentication status
    public static final List<String> TERMINATING_STATUSES = Arrays.asList("COMPLETED", "FAILED", "CANCELED");

    public enum Result {
        allow,
        deny
    }

    public enum Status {
        bypass,
        disabled,
        locked_out
    }

    public enum PreAuthResult {
        auth,
        allow,
        deny,
        unknown
    }

    /**
     * Constants for Futurae configuration properties.
     */
    public enum ConfigProperties {

        SERVICE_HOSTNAME(1, "serviceHostname", "Service Hostname",
                "Enter the Service hostname (which is the host part of the Service Base URL)."),
        SERVICE_ID(2, "serviceId", "Service ID",
                "Enter the Service ID of the Futurae service."),
        AUTH_API_KEY(3, "authApiKey", "Auth API Key",
                "Enter the Auth API Key of the Futurae service."),
        ADMIN_API_KEY(4, "adminApiKey", "Admin API Key",
                "Enter the Admin API Key of the Futurae service.");

        private final int displayOrder;
        private final String name;
        private final String displayName;
        private final String description;

        ConfigProperties(int displayOrder, String name, String displayName, String description) {

            this.displayOrder = displayOrder;
            this.name = name;
            this.displayName = displayName;
            this.description = description;
        }

        public int getDisplayOrder() {

            return displayOrder;
        }

        public String getName() {

            return name;
        }

        public String getDisplayName() {

            return displayName;
        }

        public String getDescription() {

            return description;
        }
    }

    /**
     * Object holding authentication mobile response status.
     */
    public enum AuthenticationStatus {

        INVALID_TOKEN("INVALID_TOKEN", "Authentication failed due to an internal server error. " +
                "To fix this, contact your system administrator."),
        INVALID_REQUEST("INVALID_REQUEST", "Invalid username provided"),
        INVALID_USER("INVALID_USER", "User does not exist in Futurae"),
        PENDING("PENDING", "Authentication with Futurae is in progress. Awaiting for the user to " +
                "authenticate via the registered device"),
        COMPLETED("COMPLETED", "Authentication successfully completed."),
        PENDING_ENROLLMENT("PENDING_ENROLLMENT", "Awaiting the user to scan the QR code with the Futurae mobile app to complete enrollment."),
        DENY("DENY", "Authentication failed. Try again."),
        WAITING("WAITING", "Authentication with Futurae is in progress. Awaiting for the user to " +
                "authenticate via the registered device"),
        FAILED("FAILED", "Authentication failed. Try again."),
        CANCELED("CANCELED", "Authentication with Futurae was cancelled by the user.");

        private final String name;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param name    Relevant error code.
         * @param message Relevant error message.
         */
        AuthenticationStatus(String name, String message) {

            this.name = name;
            this.message = message;
        }

        public String getName() {

            return name;
        }

        public String getMessage() {

            return message;
        }
    }

    /**
     * Includes the error codes and the corresponding error messages.
     */
    public enum ErrorMessages {

        AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE("65001",
                "Authentication failed when redirecting the user to the login page."),
        AUTHENTICATION_FAILED_BUILDING_LOGIN_URL_FAILURE("HYPR-65002",
                "Authentication when building the login URL."),
        USER_NOT_FOUND("65002", "User not found in the system."),
        USER_ACCOUNT_LOCKED("65003", "User account is locked. Please contact your system administrator."),
        AUTHENTICATION_FAILED_RETRIEVING_PRE_AUTH_FAILURE("65003",
                "Authentication failed while retrieving the available auth options from Futurae."),
        // TODO: Fix error messages
        NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP("65015", "No authenticated user found"),
        ERROR_CODE_NO_AUTHENTICATED_USER("65024", "Can not find the authenticated user."),
        ERROR_CODE_NO_FEDERATED_USER("65025", "No federated user found."),
        ERROR_CODE_NO_USER_TENANT("65026", "Can not find the authenticated user's tenant domain."),
        ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65021", "No IDP found with the name IDP: " +
                "%s in tenant: %s"),
        ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION("65023", "Cannot handle federated user " +
                "authentication with as JIT Provision is not enabled for the IDP: in the tenant: %s."),
        AUTHENTICATION_FAILED_SENDING_PUSH_NOTIFICATION_FAILURE("65004",
                "Authentication failed while sending push notification."),
        AUTHENTICATION_FAILED_SENDING_PUSH_NOTIFICATION_INVALID_USER("65005",
                "Authentication failed when sending a push notification to the registered device due to " +
                        "providing an invalid username."),
        AUTHENTICATION_FAILED_RETRIEVING_HASH_ALGORITHM_FAILURE("65006",
                "Authentication failed retrieving the hash algorithm."),
        AUTHENTICATION_FAILED_RETRIEVING_AUTHENTICATION_STATUS_FAILURE("65007",
                "Authentication failed when retrieving status of the user authentication."),
        FUTURAE_SERVICE_HOSTNAME_INVALID_FAILURE("65008", "Provided Futurae service hostname is invalid."),
        FUTURAE_SERVICE_ID_INVALID_FAILURE("65009", "Provided Futurae Service ID is invalid."),
        FUTURAE_AUTH_API_KEY_INVALID_FAILURE("65010",
                "Provided Futurae Auth API Key is either invalid or expired"),
        FUTURAE_ADMIN_API_KEY_INVALID_FAILURE("65010",
                "Provided Futurae Admin API Key is either invalid or expired"),
        RETRIEVING_USER_STORE_FAILURE("65004", "Retrieving user store failed for the given user."),
        RETRIEVING_USER_REALM_FAILURE("65005", "Retrieving user realm failed for the given tenant."),
        RETRIEVING_REG_USER_FAILURE("65006",
                "Retrieving Futurae registered user failed for the given userId."),
        FUTURAE_ENDPOINT_API_TOKEN_INVALID_FAILURE("65010",
                "Provided Futurae API key or service ID is invalid"),
        FUTURAE_ENDPOINT_INVALID_REQUEST_FAILURE("65010",
                "Provided Futurae user details are invalid"),
        FUTURAE_ENDPOINT_INVALID_SESSION_FAILURE("65010",
                "Invalid session."),
        FUTURAE_ENDPOINT_INVALID_SERVICE_URL_FAILURE("65010",
                "Provided Futurae service hostname is invalid"),
        SERVER_ERROR_GENERAL("65011", "Server error occurred",
                "Unable to complete the action due to a server error"),
        SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS("65012",
                "Invalid authenticator configurations",
                "Extracted Futurae authenticator configurations missing required information"),
        SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES("65013",
                "Invalid authenticator configurations",
                "Extracted Futurae authentication properties from the context missing either authStatus or " +
                        "futuraeSessionId"),
        SERVER_ERROR_CREATING_HTTP_CLIENT("65014", "Error while creating http client.",
                "Server error encountered while creating http client."),
        SERVER_ERROR_GETTING_HTTP_CLIENT("65015", "Error while getting the http client.",
                "Error preparing http client to publish events."),
        CLIENT_ERROR_INVALID_SESSION_KEY("60001", "Invalid session key provided.",
                "The provided session key doesn't exist.");
        private final String code;
        private final String message;
        private final String description;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
            description = null;
        }

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return "HYPR.HYPR_API_PREFIX + code";
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        /**
         * To get the description of specific error.
         *
         * @return Error description.
         */
        public String getDescription() {

            return description;
        }

        @Override
        public String toString() {

            return code + " | " + message;
        }
    }

}
