package org.wso2.custom.authenticator.futurae.common.exception;

/**
 * An exception class which is used to send a Futurae specific error code and error message when the Futurae connector
 * encountered any errors with regard to HTTP Client connections.
 */
public class FuturaeClientException extends Exception {

    private String code;
    private String description;

    /**
     * An overloaded constructor which is used to throw an error code and error message once the Futurae connector
     * unable to proceed the authentication with Futurae due to HTTP client connection issue.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     */
    public FuturaeClientException(String message, String code) {

        super(message);
        this.code = code;
    }

    /**
     * An overloaded constructor which is used to throw an error code, error message and error description once the
     * Futurae connector unable to proceed the authentication with Futurae due to HTTP client connection issue.
     *
     * @param code        An error code specified to the authenticator.
     * @param message     An error message specified to the authenticator.
     * @param description An in-detail error description specified to the authenticator.
     */
    public FuturaeClientException(String message, String description, String code) {

        super(message);
        this.description = description;
        this.code = code;
    }

    /**
     * An overloaded constructor which is used to throw an error code, error message, error description and
     * throwable cause once the Futurae connector unable to proceed the authentication with Futurae due to
     * HTTP client connection issue.
     *
     * @param code        An error code specified to the authenticator.
     * @param message     An error message specified to the authenticator.
     * @param description An in-detail error description specified to the authenticator.
     * @param cause       Thrown exception.
     */
    public FuturaeClientException(String message, String description, String code, Throwable cause) {

        super(message, cause);
        this.description = description;
        this.code = code;
    }
}
