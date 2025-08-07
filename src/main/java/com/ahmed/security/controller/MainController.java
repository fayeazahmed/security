package com.ahmed.security.controller;

import com.ahmed.security.dto.AuthResponseDto;
import com.ahmed.security.dto.UserAuthDto;
import com.ahmed.security.model.User;
import com.ahmed.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping("/protected")
    public ResponseEntity<String> protectedPath() {
        return ResponseEntity.ok("Hello User");
    }

    @GetMapping("/protected/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> protectedPathAdmin() {
        return ResponseEntity.ok("Hello Admin");
    }
}
