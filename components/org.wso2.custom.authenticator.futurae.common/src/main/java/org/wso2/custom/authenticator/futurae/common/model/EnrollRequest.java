package org.wso2.custom.authenticator.futurae.common.model;

/**
 * Request model for POST /srv/auth/v1/user/enroll.
 *
 * Use {@link #forNewUser()} to enroll a brand-new Futurae user.
 * Use {@link #forExistingUser(String)} to enroll a new device for an existing user.
 * All other fields are optional and can be set via their respective setters.
 */
public class EnrollRequest {

    // Required only when enrolling an existing user
    private final String user_id;

    // Optional — new user enrollment only
    private String username;
    private String display_name;

    // Optional — shared
    private Integer valid_secs;
    private Boolean short_code;
    private String success_callback_url;
    private Boolean enrollment_flow_binding_enabled;
    private Boolean account_recovery_flow_binding_enabled;

    private EnrollRequest(String user_id) {
        this.user_id = user_id;
    }

    public static EnrollRequest forNewUser() {
        return new EnrollRequest(null);
    }

    public static EnrollRequest forExistingUser(String user_id) {
        return new EnrollRequest(user_id);
    }

    public String getUser_id() {
        return user_id;
    }

    public String getUsername() {
        return username;
    }

    public EnrollRequest setUsername(String username) {
        this.username = username;
        return this;
    }

    public String getDisplay_name() {
        return display_name;
    }

    public EnrollRequest setDisplay_name(String display_name) {
        this.display_name = display_name;
        return this;
    }

    public Integer getValid_secs() {
        return valid_secs;
    }

    public EnrollRequest setValid_secs(Integer valid_secs) {
        this.valid_secs = valid_secs;
        return this;
    }

    public Boolean getShort_code() {
        return short_code;
    }

    public EnrollRequest setShort_code(Boolean short_code) {
        this.short_code = short_code;
        return this;
    }

    public String getSuccess_callback_url() {
        return success_callback_url;
    }

    public EnrollRequest setSuccess_callback_url(String success_callback_url) {
        this.success_callback_url = success_callback_url;
        return this;
    }

    public Boolean getEnrollment_flow_binding_enabled() {
        return enrollment_flow_binding_enabled;
    }

    public EnrollRequest setEnrollment_flow_binding_enabled(Boolean enrollment_flow_binding_enabled) {
        this.enrollment_flow_binding_enabled = enrollment_flow_binding_enabled;
        return this;
    }

    public Boolean getAccount_recovery_flow_binding_enabled() {
        return account_recovery_flow_binding_enabled;
    }

    public EnrollRequest setAccount_recovery_flow_binding_enabled(Boolean account_recovery_flow_binding_enabled) {
        this.account_recovery_flow_binding_enabled = account_recovery_flow_binding_enabled;
        return this;
    }
}
