package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Response model for POST /srv/auth/v1/user/enroll_status.
 *
 * result values:
 *   "success"  — user has scanned the QR code and enrollment is complete.
 *   "pending"  — user has not yet scanned the QR code.
 *   "expired"  — the enrollment link has expired.
 */
public class EnrollStatusResponse {

    private String result;
    private String device_id;

    public EnrollStatusResponse() {
    }

    public String getResult() {
        return result;
    }

    public String getDevice_id() {
        return device_id;
    }
}