package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for POST /srv/auth/v1/user/preauth.
 * Either user_id or username must be supplied, but not both.
 * trusted_device_token is optional.
 */
public class PreAuthRequest {

    private final String user_id;
    private final String username;
    private String trusted_device_token;

    private PreAuthRequest(String user_id, String username) {
        this.user_id = user_id;
        this.username = username;
    }

    public static PreAuthRequest byUserId(String user_id) {
        return new PreAuthRequest(user_id, null);
    }

    public static PreAuthRequest byUsername(String username) {
        return new PreAuthRequest(null, username);
    }

    public PreAuthRequest withTrustedDeviceToken(String trusted_device_token) {
        this.trusted_device_token = trusted_device_token;
        return this;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public String getTrusted_device_token() {
        return trusted_device_token;
    }
}
