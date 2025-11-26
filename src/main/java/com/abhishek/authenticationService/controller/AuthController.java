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
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import static com.abhishek.authenticationService.constant.Constants.*;

@Slf4j
@RestController
@RequestMapping(ENDPOINT_AUTH)
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping(ENDPOINT_REGISTER)
    public ResponseEntity<ApiResponse<Void>> register(@RequestBody @Valid RegisterRequest request) {
        log.info("POST {} - Registering user: {}", AUTH_REGISTER, request.getEmail());

        authService.registerUser(request);

        log.debug("User registration completed successfully: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.<Void>builder()
                .message(MSG_USER_REGISTERED)
                .build());
    }

    @PostMapping(ENDPOINT_LOGIN)
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest request) {
        log.info("POST {} - Login attempt for user: {}", AUTH_LOGIN, request.getEmail());

        LoginResponse response = authService.login(request);

        log.debug("Login successful for user: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.<LoginResponse>builder()
                .message(MSG_LOGIN_SUCCESSFUL)
                .data(response)
                .build());
    }

    @PostMapping(ENDPOINT_ASSIGN_ROLE)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Object>> assignRole(@Valid @RequestBody AssignRoleRequest request) {
        log.info("POST {} - Assigning roles to user: {}", ENDPOINT_AUTH + ENDPOINT_ASSIGN_ROLE, request.getEmail());

        authService.assignRoles(request.getEmail(), request.getRoles());

        log.debug("Roles assigned successfully to user: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.builder()
                .message(MSG_ROLES_UPDATED)
                .data(null)
                .build());
    }

    @GetMapping(ENDPOINT_USERS)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<?>> getUsers() {
        log.info("GET {} - Fetching all users", ENDPOINT_AUTH + ENDPOINT_USERS);

        var users = authService.getAllUsers();

        log.debug("Returning {} users", users.size());
        return ResponseEntity.ok(ApiResponse.builder()
                .message(MSG_USERS_FETCHED)
                .data(users)
                .build());
    }

    @GetMapping(ENDPOINT_USER_ID)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<?>> getUserById(@PathVariable String userId) {
        log.info("GET {} - Fetching user with Id {}", ENDPOINT_AUTH + ENDPOINT_USER_ID, userId);

        var user = authService.getUserById(userId);

        log.debug("User found with name {} for id {}", user, user);

        return ResponseEntity.ok(ApiResponse.builder()
                .message(MSG_USERS_FETCHED)
                .data(user)
                .build());
    }
}
