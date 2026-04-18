package org.wso2.custom.authenticator.futurae.common.util;

import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeAuthnFailedException;

public class FuturaeUtils {

    public static FuturaeAuthnFailedException getFuturaeAuthnFailedException(
            FuturaeAuthenticatorConstants.ErrorMessages errorMessage) {

        return new FuturaeAuthnFailedException(errorMessage.getCode(), errorMessage.getMessage());
    }

    public static FuturaeAuthnFailedException getFuturaeAuthnFailedException(
            FuturaeAuthenticatorConstants.ErrorMessages errorMessage, Exception e) {

        return new FuturaeAuthnFailedException(errorMessage.getCode(), errorMessage.getMessage(), e);
    }
}

