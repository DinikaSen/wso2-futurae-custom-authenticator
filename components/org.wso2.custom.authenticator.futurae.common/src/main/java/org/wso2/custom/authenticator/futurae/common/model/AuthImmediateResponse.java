package org.wso2.custom.authenticator.futurae.common.model;

import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;

/**
 * Models the immediate 200 response returned when the user can bypass Futurae authentication,
 * has it disabled, or is locked out — i.e. no pending session is created.
 */
public class AuthImmediateResponse {

    private final FuturaeAuthenticatorConstants.Result result;
    private final FuturaeAuthenticatorConstants.Status status;
    private final String status_msg;

    public AuthImmediateResponse(FuturaeAuthenticatorConstants.Result result,
                                 FuturaeAuthenticatorConstants.Status status, String status_msg) {
        this.result = result;
        this.status = status;
        this.status_msg = status_msg;
    }

    public FuturaeAuthenticatorConstants.Result getResult() {
        return result;
    }

    public FuturaeAuthenticatorConstants.Status getStatus() {
        return status;
    }

    public String getStatus_msg() {
        return status_msg;
    }

    public boolean isAllowed() {
        return FuturaeAuthenticatorConstants.Result.allow == result;
    }
}
