package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Response model for POST /srv/auth/v1/user/enroll.
 * Applies to both new user and existing user enrollment.
 */
public class EnrollResponse {

    private String activation_code;
    private String enrollment_id;
    private String activation_code_uri;
    private String activation_universal_link;
    private String activation_qrcode_data_uri;
    private String activation_qrcode_url;
    private long expiration;
    private String user_id;
    private String username;

    // Present only if short_code=true was set in the request
    private String activation_code_short;

    public EnrollResponse() {
    }

    public String getActivation_code() {
        return activation_code;
    }

    public String getEnrollment_id() {
        return enrollment_id;
    }

    public String getActivation_code_uri() {
        return activation_code_uri;
    }

    public String getActivation_universal_link() {
        return activation_universal_link;
    }

    public String getActivation_qrcode_data_uri() {
        return activation_qrcode_data_uri;
    }

    public String getActivation_qrcode_url() {
        return activation_qrcode_url;
    }

    public long getExpiration() {
        return expiration;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public String getActivation_code_short() {
        return activation_code_short;
    }
}
