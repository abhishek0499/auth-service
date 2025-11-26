package com.abhishek.authenticationService.exception;

/**
 * Custom exception for user-related errors
 */
public class UserAlreadyExistsException extends RuntimeException {
    
    private final String email;
    
    public UserAlreadyExistsException(String email) {
        super(String.format("User with email '%s' already exists", email));
        this.email = email;
    }
    
    public String getEmail() {
        return email;
    }
}
