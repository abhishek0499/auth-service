package com.abhishek.authenticationService.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.Set;

@Document(collection = "users")
@Data
public class User {
    @Id
    private String id;
    private String email;
    private String password; // stored as bcrypt hash
    private String name;
    private String phone;
    private Set<String> roles; // e.g., ["ADMIN","CANDIDATE"]
    private LocalDateTime createdAt;
}