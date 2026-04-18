package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Response model for GET /srv/auth/v1/users.
 */
public class UserSearchResponse {

    private String user_id;
    private String username;
    private String status;

    public UserSearchResponse() {
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public String getStatus() {
        return status;
    }
}
