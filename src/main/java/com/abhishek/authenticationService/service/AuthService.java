package com.abhishek.authenticationService.service;

import com.abhishek.authenticationService.dto.LoginRequest;
import com.abhishek.authenticationService.dto.LoginResponse;
import com.abhishek.authenticationService.dto.RegisterRequest;
import com.abhishek.authenticationService.dto.UserResponse;
import com.abhishek.authenticationService.exception.InvalidCredentialsException;
import com.abhishek.authenticationService.exception.UserAlreadyExistsException;
import com.abhishek.authenticationService.exception.UserNotFoundException;
import com.abhishek.authenticationService.model.User;
import com.abhishek.authenticationService.repository.UserRepository;
import com.abhishek.authenticationService.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.abhishek.authenticationService.constant.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public void registerUser(RegisterRequest registerRequest) {
        log.info("Registering user with email: {}", registerRequest.getEmail());
        
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            log.warn("Registration failed - email already in use: {}", registerRequest.getEmail());
            throw new UserAlreadyExistsException(registerRequest.getEmail());
        }
        
        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setName(registerRequest.getName());
        user.setPhone(registerRequest.getPhone());
        user.setRoles(Set.of(ROLE_CANDIDATE));
        user.setCreatedAt(LocalDateTime.now());
        
        User savedUser = userRepository.save(user);
        log.info("User registered successfully: {}", savedUser.getEmail());
    }

    public LoginResponse login(LoginRequest loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());
        
        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> {
                    log.warn("Login failed - user not found: {}", loginRequest.getEmail());
                    return new InvalidCredentialsException(loginRequest.getEmail(), "User not found");
                });
        
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            log.warn("Login failed - invalid password for user: {}", loginRequest.getEmail());
            throw new InvalidCredentialsException(loginRequest.getEmail(), "Invalid password");
        }
        
        String token = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRoles());
        log.info("User logged in successfully: {}", loginRequest.getEmail());
        
        return new LoginResponse(token, jwtUtil.getExpirationMs());
    }

    @Transactional
    public void assignRoles(String email, Set<String> roles) {
        log.info("Assigning roles to user: {}", email);
        
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.error("Role assignment failed - user not found: {}", email);
                    return new UserNotFoundException(email);
                });
        
        user.setRoles(roles);
        userRepository.save(user);
        
        log.info("Roles assigned successfully to user: {}", email);
    }

    public List<UserResponse> getAllUsers() {
        log.info("Fetching all users");
        
        List<UserResponse> users = userRepository.findAll().stream()
                .map(user -> new UserResponse(user.getId(), user.getEmail(), user.getName(), user.getRoles()))
                .collect(Collectors.toList());
        
        log.info("Fetched {} users", users.size());
        return users;
    }
}
