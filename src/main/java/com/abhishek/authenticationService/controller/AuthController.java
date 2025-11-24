package com.abhishek.authenticationService.controller;

import com.abhishek.authenticationService.dto.AssignRoleRequest;
import com.abhishek.authenticationService.dto.LoginRequest;
import com.abhishek.authenticationService.dto.LoginResponse;
import com.abhishek.authenticationService.dto.RegisterRequest;
import com.abhishek.authenticationService.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        authService.register(req);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest req) {
        LoginResponse resp = authService.login(req);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/assign-role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignRole(@Valid @RequestBody AssignRoleRequest req) {
        authService.assignRoles(req.getEmail(), req.getRoles());
        return ResponseEntity.ok(Map.of("status", "roles_updated"));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUsers() {
        return ResponseEntity.ok(authService.getAllUsers());
    }
}