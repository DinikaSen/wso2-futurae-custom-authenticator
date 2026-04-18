package org.wso2.custom.authenticator.futurae.common.model;

import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;

import java.util.List;

/**
 * Response model for POST /srv/auth/v1/user/preauth.
 *
 * The result field determines which optional fields are present:
 *   auth    — allowed_factors, devices, and recommended_factor are populated.
 *   allow   — user_status may be present (bypass) if the user bypasses authentication.
 *   deny    — user_status is present (disabled or locked_out).
 *   unknown — no additional fields; the user is not recognized by Futurae.
 */
public class PreAuthResponse {

    private FuturaeAuthenticatorConstants.PreAuthResult result;

    // Present when result is allow or deny
    private FuturaeAuthenticatorConstants.Status user_status;

    // Present when result is auth
    private List<String> allowed_factors;
    private List<Device> devices;
    private String recommended_factor;

    // No-arg constructor required for Gson deserialization
    public PreAuthResponse() {
    }

    public PreAuthResponse(FuturaeAuthenticatorConstants.PreAuthResult result) {
        this.result = result;
    }

    public FuturaeAuthenticatorConstants.PreAuthResult getResult() {
        return result;
    }

    public FuturaeAuthenticatorConstants.Status getUser_status() {
        return user_status;
    }

    public void setUser_status(FuturaeAuthenticatorConstants.Status user_status) {
        this.user_status = user_status;
    }

    public List<String> getAllowed_factors() {
        return allowed_factors;
    }

    public void setAllowed_factors(List<String> allowed_factors) {
        this.allowed_factors = allowed_factors;
    }

    public List<Device> getDevices() {
        return devices;
    }

    public void setDevices(List<Device> devices) {
        this.devices = devices;
    }

    public String getRecommended_factor() {
        return recommended_factor;
    }

    public void setRecommended_factor(String recommended_factor) {
        this.recommended_factor = recommended_factor;
    }
}
