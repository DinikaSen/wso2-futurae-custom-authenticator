package org.wso2.custom.authenticator.futurae.common.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

/**
 * An exception class which is used to send a Futurae specific error code and error message when authenticator unable
 * to proceed the authentication.
 */
public class FuturaeAuthnFailedException extends AuthenticationFailedException {

    /**
     * An overloaded constructor which is used to throw an error code,error message and throwable cause once
     * authenticator unable to proceed the authentication with Futurae.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     * @param cause   Thrown exception.
     */
    public FuturaeAuthnFailedException(String code, String message, Throwable cause) {

        super(code, message, cause);
    }

    /**
     * An overloaded constructor which is used to throw an error code and error message once
     * authenticator unable to proceed the authentication with Futurae.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     */
    public FuturaeAuthnFailedException(String code, String message) {

        super(code, message);
    }
}
