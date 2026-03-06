package com.webbinroot.ocisigner.model;

public enum AuthType {
    API_KEY("API Key"),
    SECURITY_TOKEN("Security Token (Session)"),
    CONFIG_PROFILE("Config Profile (Auto)"),
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
