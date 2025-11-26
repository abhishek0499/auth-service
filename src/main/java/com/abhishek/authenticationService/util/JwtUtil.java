package com.abhishek.authenticationService.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

import static com.abhishek.authenticationService.constant.Constants.*;

@Slf4j
@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(@Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expirationMs) {
        this.expirationMs = expirationMs;
        this.key = resolveKey(secret);
        log.info("JwtUtil initialized with expiration: {} ms", expirationMs);
    }

    private SecretKey resolveKey(String secret) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
            log.debug("JWT secret key resolved using BASE64 decoding");
            return key;
        } catch (Exception exception) {
            log.warn("Failed to decode BASE64 secret, using UTF-8 encoding instead");
            return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String generateToken(String userId, String email, Set<String> roles) {
        log.debug("JWT token generated for user: {}", email);

        long currentTimeMillis = System.currentTimeMillis();

        String token = Jwts.builder()
                .subject(userId)
                .claim(JWT_CLAIM_EMAIL, email)
                .claim(JWT_CLAIM_ROLES, roles)
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(currentTimeMillis + expirationMs))
                .signWith(key)
                .compact();

        log.info("JWT token generated successfully for user: {}", email);
        return token;
    }

    public Claims parseClaims(String token) {
        try {
            Claims claims = (Claims) Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parse(token)
                    .getPayload();

            String userId = claims.getSubject();
            log.debug("JWT token parsed successfully for user: {}", userId);
            return claims;
        } catch (Exception exception) {
            log.error("Invalid or expired JWT token: {}", exception.getMessage());
            throw exception;
        }
    }

    public long getExpirationMs() {
        return expirationMs;
    }
}
