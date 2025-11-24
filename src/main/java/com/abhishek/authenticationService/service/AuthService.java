package com.abhishek.authenticationService.service;

import com.abhishek.authenticationService.dto.LoginRequest;
import com.abhishek.authenticationService.dto.LoginResponse;
import com.abhishek.authenticationService.dto.RegisterRequest;
import com.abhishek.authenticationService.dto.UserResponse;
import com.abhishek.authenticationService.model.User;
import com.abhishek.authenticationService.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

import static com.abhishek.authenticationService.constant.Constants.CANDIDATE;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public void register(RegisterRequest registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new IllegalArgumentException("Email already in use");
        }
        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setName(registerRequest.getName());
        user.setPhone(registerRequest.getPhone());
        user.setRoles(Set.of(CANDIDATE));
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    public LoginResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }
        String token = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getRoles());
        return new LoginResponse(token, jwtUtil.getExpirationMs());
    }

    @Transactional
    public void assignRoles(String email, Set<String> roles) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
        user.setRoles(roles);
        userRepository.save(user);
    }

    public java.util.List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(u -> new UserResponse(u.getId(), u.getEmail(), u.getName(), u.getRoles()))
                .collect(Collectors.toList());
    }
}