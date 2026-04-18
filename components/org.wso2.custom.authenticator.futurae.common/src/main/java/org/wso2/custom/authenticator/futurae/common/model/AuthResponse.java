package org.wso2.custom.authenticator.futurae.common.model;

public class AuthResponse {

    private String session_id;
    private String mobile_auth_uri;
    private String mobile_auth_universal_link;
    private String multi_numbered_challenge_value;

    // No-arg constructor required for Gson deserialization
    public AuthResponse() {
    }

    public String getSession_id() {
        return session_id;
    }

    public String getMobile_auth_uri() {
        return mobile_auth_uri;
    }

    public String getMobile_auth_universal_link() {
        return mobile_auth_universal_link;
    }

    public String getMulti_numbered_challenge_value() {
        return multi_numbered_challenge_value;
    }
}
