package com.abhishek.authenticationService.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class AssignRoleRequest {
    @NotBlank
    private String email;

    @NotEmpty
    private Set<String> roles; // e.g., ["ADMIN", "MANAGER"]
}
