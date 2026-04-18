package org.wso2.custom.authenticator.futurae.rest.common;

import org.slf4j.MDC;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;

import java.util.UUID;

/**
 * Util class.
 */
public class Util {

    /**
     * Get correlation id of current thread.
     *
     * @return Correlation-id.
     */
    public static String getCorrelation() {

        if (isCorrelationIDPresent()) {
            return MDC.get(FuturaeAuthenticatorConstants.CORRELATION_ID_KEY).toString();
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Check whether correlation id present in the log MDC.
     *
     * @return whether the correlation id is present.
     */
    public static boolean isCorrelationIDPresent() {

        return MDC.get(FuturaeAuthenticatorConstants.CORRELATION_ID_KEY) != null;
    }
}
