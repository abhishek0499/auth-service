package com.abhishek.authenticationService.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email Id is mandatory")
    private String email;

    @NotBlank(message = "Password is mandatory")
    private String password;
}