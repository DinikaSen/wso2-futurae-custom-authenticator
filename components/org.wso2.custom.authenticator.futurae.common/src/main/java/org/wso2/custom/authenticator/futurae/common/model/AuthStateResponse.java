package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Response model for POST /srv/auth/v1/user/auth/status.
 */
public class AuthStateResponse {

    private String result;
    private String status;
    private String status_msg;
    private String device_id;
    private String user_id;
    private String trusted_device_token;
    private String user_presence_verification;
    private Object device_integrity;

    public AuthStateResponse() {
    }

    public String getResult() {
        return result;
    }

    public String getStatus() {
        return status;
    }

    public String getStatus_msg() {
        return status_msg;
    }

    public String getDevice_id() {
        return device_id;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getTrusted_device_token() {
        return trusted_device_token;
    }

    public String getUser_presence_verification() {
        return user_presence_verification;
    }

    public Object getDevice_integrity() {
        return device_integrity;
    }
}
