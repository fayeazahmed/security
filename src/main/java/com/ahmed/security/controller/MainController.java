package com.ahmed.security.controller;

import com.ahmed.security.dto.AuthResponseDto;
import com.ahmed.security.dto.UserAuthDto;
import com.ahmed.security.model.User;
import com.ahmed.security.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class MainController {
    private final AuthService authService;

    @GetMapping("/authenticate")
    ResponseEntity<User> getAuthenticatedUser() {
        return ResponseEntity.ok(authService.getAuthenticatedUser());
    }

    @PostMapping("/authenticate")
    ResponseEntity<AuthResponseDto> authenticate(@RequestBody UserAuthDto userAuthDto) {
        log.info("Authentication request: {}", userAuthDto);

        return ResponseEntity.ok(authService.authenticate(userAuthDto));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> protectedPathAdmin() {
        return ResponseEntity.ok("Hello Admin");
    }

    @GetMapping("/oauth2")
    public ResponseEntity<Map<String, Object>> authenticateOAuth2(Authentication authentication) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("username", authentication.getName());
        attributes.put("roles", authentication.getAuthorities());
        return ResponseEntity.ok(attributes);
    }

    @GetMapping("/logout")
    public ResponseEntity<Void> logoutOAuth2(HttpServletResponse response) {
        Cookie cookie = new Cookie("JWT_TOKEN", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.noContent().build();
    }
}
