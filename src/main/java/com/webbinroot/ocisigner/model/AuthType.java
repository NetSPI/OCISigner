package com.webbinroot.ocisigner.model;

public enum AuthType {
    CONFIG_PROFILE("Config Profile (Auto)"),
    API_KEY("API Key"),
    SECURITY_TOKEN("Session Token"),
    INSTANCE_PRINCIPAL("Instance Principal"),
    RESOURCE_PRINCIPAL("Resource Principal");

    private final String label;

    AuthType(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        // Example output: "API Key"
        return label;
    }
}
