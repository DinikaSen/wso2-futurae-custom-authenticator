package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for POST /srv/auth/v1/user/enroll_status.
 * Either user_id or username must be provided (not both), along with enrollment_id.
 */
public class EnrollStatusRequest {

    private String user_id;
    private String username;
    private final String enrollment_id;

    private EnrollStatusRequest(String enrollment_id) {
        this.enrollment_id = enrollment_id;
    }

    public static EnrollStatusRequest byUserId(String user_id, String enrollment_id) {
        EnrollStatusRequest request = new EnrollStatusRequest(enrollment_id);
        request.user_id = user_id;
        return request;
    }

    public static EnrollStatusRequest byUsername(String username, String enrollment_id) {
        EnrollStatusRequest request = new EnrollStatusRequest(enrollment_id);
        request.username = username;
        return request;
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public String getEnrollment_id() {
        return enrollment_id;
    }
}