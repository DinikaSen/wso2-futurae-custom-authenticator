package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for POST /srv/auth/v1/user/unenroll.
 * Either user_id or username must be provided (not both), along with a device_id.
 */
public class UnenrollDeviceRequest {

    private String user_id;
    private String username;
    private final String device_id;

    private UnenrollDeviceRequest(String device_id) {
        this.device_id = device_id;
    }

    public static UnenrollDeviceRequest byUserId(String user_id, String device_id) {
        UnenrollDeviceRequest request = new UnenrollDeviceRequest(device_id);
        request.user_id = user_id;
        return request;
    }

    public static UnenrollDeviceRequest byUsername(String username, String device_id) {
        UnenrollDeviceRequest request = new UnenrollDeviceRequest(device_id);
        request.username = username;
        return request;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public String getDevice_id() {
        return device_id;
    }
}
