package com.abhishek.authenticationService.exception;

/**
 * Custom exception for invalid credentials during login
 */
public class InvalidCredentialsException extends RuntimeException {

    private final String email;
    private final String reason;

    public InvalidCredentialsException(String email, String reason) {
        super(String.format("Invalid credentials for user '%s': %s", email, reason));
        this.email = email;
        this.reason = reason;
    }

    public String getEmail() {
        return email;
    }

    public String getReason() {
        return reason;
    }
}
