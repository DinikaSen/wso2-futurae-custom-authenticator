package org.wso2.custom.authenticator.futurae.common.model;

import java.util.List;

/**
 * Represents a user's enrolled device returned in a PreAuth response.
 */
public class Device {

    private String device_id;
    private String display_name;
    private List<String> capabilities;
    private String type;
    private String version;
    private boolean version_supported;
    private String device_integrity;
    private long device_integrity_updated_at;
    private long enrolled_at;

    // No-arg constructor required for Gson deserialization
    public Device() {
    }

    public String getDevice_id() {
        return device_id;
    }

    public String getDisplay_name() {
        return display_name;
    }

    public List<String> getCapabilities() {
        return capabilities;
    }

    public String getType() {
        return type;
    }

    public String getVersion() {
        return version;
    }

    public boolean isVersion_supported() {
        return version_supported;
    }

    public String getDevice_integrity() {
        return device_integrity;
    }

    public long getDevice_integrity_updated_at() {
        return device_integrity_updated_at;
    }

    public long getEnrolled_at() {
        return enrolled_at;
    }
}
