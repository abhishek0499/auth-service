package com.abhishek.authenticationService.controller;

import com.abhishek.authenticationService.dto.ApiResponse;
import com.abhishek.authenticationService.dto.AssignRoleRequest;
import com.abhishek.authenticationService.dto.LoginRequest;
import com.abhishek.authenticationService.dto.LoginResponse;
import com.abhishek.authenticationService.dto.RegisterRequest;
import com.abhishek.authenticationService.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@RequestBody @Valid RegisterRequest req) {
        log.debug("Registering User");
        authService.registerUser(req);
        return ResponseEntity.ok(ApiResponse.<Void>builder()
                .message("User registered successfully")
                .build());
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest req) {
        log.debug("Logging User");
        LoginResponse resp = authService.login(req);
        return ResponseEntity.ok(ApiResponse.<LoginResponse>builder()
                .message("Login successful")
                .data(resp)
                .build());
    }

    @PostMapping("/assign-role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Object>> assignRole(@Valid @RequestBody AssignRoleRequest req) {
        log.debug("Assigning role to User");
        authService.assignRoles(req.getEmail(), req.getRoles());
        return ResponseEntity.ok(ApiResponse.builder()
                .message("Roles updated successfully")
                .data(null)
                .build());
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<?>> getUsers() {
        log.debug("Get All Users");
        return ResponseEntity.ok(ApiResponse.builder()
                .message("Users fetched successfully")
                .data(authService.getAllUsers())
                .build());
    }
}