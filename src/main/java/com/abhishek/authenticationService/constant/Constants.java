package com.abhishek.authenticationService.constant;

/**
 * Centralized constants for the Authentication Service
 */
public final class Constants {

    private Constants() {
        // Prevent instantiation
    }

    public static final String ROLE_CANDIDATE = "CANDIDATE";
    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_MANAGER = "MANAGER";
    public static final String ROLE_PREFIX = "ROLE_";

    public static final String JWT_CLAIM_EMAIL = "email";
    public static final String JWT_CLAIM_ROLES = "roles";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int BEARER_TOKEN_START_INDEX = 7;

    public static final String MSG_USER_REGISTERED = "User registered successfully";
    public static final String MSG_LOGIN_SUCCESSFUL = "Login successful";
    public static final String MSG_ROLES_UPDATED = "Roles updated successfully";
    public static final String MSG_USERS_FETCHED = "Users fetched successfully";

    public static final String ENDPOINT_AUTH = "/auth";
    public static final String ENDPOINT_REGISTER = "/register";
    public static final String ENDPOINT_LOGIN = "/login";
    public static final String ENDPOINT_ASSIGN_ROLE = "/assign-role";
    public static final String ENDPOINT_USERS = "/users";
    public static final String ENDPOINT_USER_ID = "/user/{userId}";
    public static final String AUTH_LOGIN = "/auth/login";
    public static final String AUTH_REGISTER = "/auth/register";
    public static final String ACTUATOR = "/actuator/**";

    public static final String[] CORS_ALLOWED_METHODS = { "GET", "POST", "PUT", "DELETE", "OPTIONS" };
    public static final String[] CORS_EXPOSED_HEADERS = { "Authorization", "Content-Type" };
}
