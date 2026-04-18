package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for GET /srv/auth/v1/users.
 * username is the only supported filter and is required.
 */
public class UserSearchRequest {

    private final String username;

    public UserSearchRequest(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}