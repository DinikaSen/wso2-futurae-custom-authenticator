package org.wso2.custom.authenticator.futurae.common.model;

public class AuthRequest {

    private String username;
    private String user_id;
    private final String factor;
    private final String device_id = "auto";

    private AuthRequest(String factor) {
        this.factor = factor;
    }

    public static AuthRequest byUsername(String username, String factor) {
        AuthRequest request = new AuthRequest(factor);
        request.username = username;
        return request;
    }

    public static AuthRequest byUserId(String user_id, String factor) {
        AuthRequest request = new AuthRequest(factor);
        request.user_id = user_id;
        return request;
    }

    public String getUsername() {
        return username;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getFactor() {
        return factor;
    }

    public String getDevice_id() {
        return device_id;
    }
}
