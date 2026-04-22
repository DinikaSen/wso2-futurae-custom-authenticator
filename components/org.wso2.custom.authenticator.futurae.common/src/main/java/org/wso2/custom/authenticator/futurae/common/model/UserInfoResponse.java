package org.wso2.custom.authenticator.futurae.common.model;

import java.util.List;

/**
 * Response model for GET /srv/auth/v1/users/{id}.
 *
 * Returns the status and enrolled devices of the Futurae user identified by the given Futurae user ID.
 * The {@code allowed_factors} and {@code devices} fields are only present when {@code status} is not
 * {@code "disabled"}.
 */
public class UserInfoResponse {

    private String username;
    private String display_name;
    private String status;
    private List<String> allowed_factors;
    private List<Device> devices;

    // No-arg constructor required for Gson deserialization
    public UserInfoResponse() {
    }

    public String getUsername() {
        return username;
    }

    public String getDisplay_name() {
        return display_name;
    }

    public String getStatus() {
        return status;
    }

    public List<String> getAllowed_factors() {
        return allowed_factors;
    }

    public List<Device> getDevices() {
        return devices;
    }
}
