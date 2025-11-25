package com.abhishek.authenticationService.exception;

/**
 * Custom exception for user not found errors
 */
public class UserNotFoundException extends RuntimeException {
    
    private final String identifier;
    
    public UserNotFoundException(String identifier) {
        super(String.format("User not found: %s", identifier));
        this.identifier = identifier;
    }
    
    public String getIdentifier() {
        return identifier;
    }
}
