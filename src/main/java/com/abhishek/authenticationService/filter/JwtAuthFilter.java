package com.abhishek.authenticationService.filter;

import com.abhishek.authenticationService.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static com.abhishek.authenticationService.constant.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        log.debug("Processing authentication for request: {}", requestURI);

        final String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            log.debug("No Bearer token found in request");
            chain.doFilter(request, response);
            return;
        }

        final String token = authorizationHeader.substring(BEARER_TOKEN_START_INDEX);

        try {
            Claims claims = jwtUtil.parseClaims(token);
            String userId = claims.getSubject();
            Object rolesObject = claims.get(JWT_CLAIM_ROLES);

            Collection<SimpleGrantedAuthority> authorities = extractAuthorities(rolesObject);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId, null,
                    authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("Authentication successful for user: {}", userId);

        } catch (Exception exception) {
            log.warn("Authentication failed for request {}: {}", requestURI, exception.getMessage());
            // token invalid or expired -> clear context and proceed unauthenticated
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }

    /**
     * Accepts roles stored either as List<String> or as comma-separated String.
     */
    @SuppressWarnings("unchecked")
    private Collection<SimpleGrantedAuthority> extractAuthorities(Object rolesObject) {
        if (rolesObject == null) {
            log.debug("No roles found in JWT claims");
            return Collections.emptyList();
        }

        if (rolesObject instanceof List<?>) {
            List<?> rawRoles = (List<?>) rolesObject;
            List<SimpleGrantedAuthority> authorities = rawRoles.stream()
                    .filter(role -> role != null)
                    .map(Object::toString)
                    .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                    .collect(Collectors.toList());

            log.debug("Extracted {} authorities from List: {}", authorities.size(), authorities);
            return authorities;
        } else {
            // fallback: treat as comma-separated string
            String rolesString = rolesObject.toString();
            List<SimpleGrantedAuthority> authorities = List.of(rolesString.split(",")).stream()
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                    .collect(Collectors.toList());

            log.debug("Extracted {} authorities from String: {}", authorities.size(), authorities);
            return authorities;
        }
    }
}
