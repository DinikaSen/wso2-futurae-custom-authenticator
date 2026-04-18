package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Response model for POST /srv/auth/v1/user/unenroll.
 *
 * result values:
 *   "success"               — device unenrolled successfully.
 *   "success_2fa_disabled"  — device unenrolled and 2FA disabled (was the only enrolled device).
 */
public class UnenrollDeviceResponse {

    private String result;

    public UnenrollDeviceResponse() {
    }

    public String getResult() {
        return result;
    }
}