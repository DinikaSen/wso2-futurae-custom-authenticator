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
    public static final String FUTURAE_USER_ID_CLAIM = "http://wso2.org/claims/futuraeUserId";
    public static final String USER_ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String AUTH_STATUS = "authStatus";
    public static final String FUTURAE_SESSION_ID = "futuraeSessionId";
    public static final String FUTURAE_ENROLLMENT_ID = "futuraeEnrollmentId";
    public static final String FUTURAE_USER_ID = "futuraeUserId";
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
    public static final String FUTURAE_DEVICE_ENROLL_STATUS_PATH = "/srv/auth/v1/user/enroll_status";
    public static final String FUTURAE_DEVICE_UNENROLL_PATH = "/srv/auth/v1/user/unenroll";
    public static final String FUTURAE_USER_PATH = "/srv/auth/v1/users";


    // Futurae supported factors
    public static final String APPROVE = "approve";
    public static final String UNENROLL_SUCCESS = "success";
    public static final String UNENROLL_SUCCESS_2FA = "success_2fa_disabled";

    // Authentication status
    public static final List<String> TERMINATING_STATUSES = Arrays.asList("COMPLETED", "FAILED", "FUTURAE_LOGIN_DENIED");

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
                "Enter the Auth API Key of the Futurae service.");

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

        PENDING("PENDING", "Authentication with Futurae is in progress. Awaiting for the user to " +
                "authenticate via the registered device"),
        COMPLETED("COMPLETED", "Authentication successfully completed."),
        PENDING_ENROLLMENT("PENDING_ENROLLMENT", "Awaiting the user to scan the QR code with " +
                "the Futurae mobile app to complete enrollment."),
        ENROLLMENT_COMPLETED("ENROLLMENT_COMPLETED", "Device enrollment completed successfully. " +
                "Proceeding to authentication."),
        FUTURAE_LOGIN_DENIED("FUTURAE_LOGIN_DENIED",
                "Authentication denied from Futurae side. Contact your administrator."),
        FAILED("FAILED", "Authentication failed. Try again.");

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

        LOGIN_REDIRECT_FAILURE("FTR-65001",
                "Authentication failed when redirecting the user to the login page."),
        LOGIN_URL_BUILD_FAILURE("FTR-65002",
                "Authentication when building the login URL."),
        USER_NOT_FOUND("FTR-65003", "User not found in the system."),
        USER_ACCOUNT_LOCKED("FTR-65004", "User account is locked. Please contact your system administrator."),
        PREAUTH_DENIED_FAILURE("FTR-65005", "Futurae user account is locked or no devices found in Futurae."),
        PREAUTH_UNKNOWN_FAILURE("FTR-65006", "User does not exist in Futurae."),
        PREAUTH_ALLOW_FAILURE("FTR-65007", "Futurae pre-auth request returned 'allow'. State not supported."),
        PREAUTH_FAILED_FAILURE("FTR-65008", "Futurae pre-auth request returned an unsupported state."),
        PREAUTH_RETRIEVAL_FAILURE("FTR-65009",
                "Authentication failed while retrieving the available auth options from Futurae."),
        AUTHENTICATED_USER_NOT_FOUND("FTR-65010", "No authenticated user found"),
        FEDERATED_USER_NOT_FOUND("FTR-65011", "No federated user found."),
        USER_TENANT_NOT_FOUND("FTR-65012", "Cannot find the authenticated user's tenant domain."),
        FEDERATED_AUTHENTICATOR_NOT_FOUND("FTR-65013", "No IDP found with the name IDP: " +
                "%s in tenant: %s"),
        FEDERATED_USER_JIT_DISABLED("FTR-65014", "Cannot handle federated user " +
                "authentication as JIT Provision is not enabled for the federated IdP."),
        CONFIG_HOSTNAME_INVALID("FTR-65015", "Provided Futurae service hostname is invalid."),
        CONFIG_SERVICE_ID_INVALID("FTR-65016", "Provided Futurae Service ID is invalid."),
        CONFIG_AUTH_API_KEY_INVALID("FTR-65017", "Provided Futurae Auth API Key is invalid."),
        USER_STORE_RETRIEVAL_FAILURE("FTR-65018", "Retrieving user store failed for the given user."),
        USER_REALM_RETRIEVAL_FAILURE("FTR-65019", "Retrieving user realm failed for the given tenant."),
        DEVICE_UNENROLL_FAILURE("FTR-65020", "Could not unenroll device from Futurae."),
        REGISTERED_USER_RETRIEVAL_FAILURE("FTR-65021",
                "Retrieving Futurae registered user failed for the given userId."),
        USER_CLAIM_UPDATE_FAILURE("FTR-65022",
                "Retrieving Futurae registered user failed for the given userId."),
        FUTURAE_USER_ID_NOT_FOUND("FTR-65023", "Could not find Futurae User ID in the context."),
        API_TOKEN_INVALID("FTR-65024", "Provided Futurae API key or service ID is invalid"),
        API_INVALID_REQUEST("FTR-65025", "Provided Futurae user details are invalid"),
        API_INVALID_SESSION("FTR-65026", "Invalid session."),
        API_INVALID_SERVICE_URL("FTR-65027", "Provided Futurae service hostname is invalid"),
        SERVER_ERROR_GENERAL("FTR-65028", "Server error occurred",
                "Unable to complete the action due to a server error"),
        SERVER_ERROR_INVALID_AUTHENTICATOR_CONFIGURATIONS("FTR-65029",
                "Invalid authenticator configurations",
                "Extracted Futurae authenticator configurations missing required information"),
        SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES("FTR-65030",
                "Invalid authenticator configurations",
                "Extracted Futurae authentication properties from the context missing either authStatus or " +
                        "futuraeSessionId"),
        SERVER_ERROR_HTTP_CLIENT_CREATE("FTR-65031", "Error while creating http client.",
                "Server error encountered while creating http client."),
        SERVER_ERROR_HTTP_CLIENT_GET("FTR-65032", "Error while getting the http client.",
                "Error preparing http client to publish events."),
        CLIENT_ERROR_INVALID_SESSION_KEY("FTR-65033", "Invalid session key provided.",
                "The provided session key doesn't exist."),
        CLAIM_RETRIEVAL_FAILURE("FTR-65034", "Retrieving user claim failed for the given user."),
        API_HMAC_SIGNING_FAILURE("FTR-65035",
                "Failed to generate HMAC-SHA256 signature for Futurae API request.",
                "");

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

            return code;
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
