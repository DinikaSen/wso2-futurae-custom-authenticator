package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for POST /srv/auth/v1/user/auth/status.
 * session_id is required.
 * user_id or username are optional, but must not both be supplied.
 */
public class AuthStateRequest {

    private final String session_id;
    private String user_id;
    private String username;

    public AuthStateRequest(String session_id) {
        this.session_id = session_id;
    }

    public AuthStateRequest withUserId(String user_id) {
        this.user_id = user_id;
        return this;
    }

    public AuthStateRequest withUsername(String username) {
        this.username = username;
        return this;
    }

    public String getSession_id() {
        return session_id;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }
}
