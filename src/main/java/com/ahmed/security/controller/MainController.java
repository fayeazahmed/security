package com.ahmed.security.controller;

import com.ahmed.security.dto.AuthResponseDto;
import com.ahmed.security.dto.UserAuthDto;
import com.ahmed.security.model.User;
import com.ahmed.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<Map<String, Object>> protectedPathOAuth2(@AuthenticationPrincipal OAuth2User principal) {
        return ResponseEntity.ok(principal.getAttributes());
    }
}
