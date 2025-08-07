package com.ahmed.security.util;

import com.ahmed.security.config.UserDetailsImpl;
import com.ahmed.security.exception.BadRequestException;
import com.ahmed.security.model.User;
import com.ahmed.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class AuthUtils {
    private final UserRepository userRepository;

    public User getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            return userRepository.findById(userDetails.getId())
                    .orElseThrow(() -> new BadRequestException("Invalid user"));
        } else {
            throw new BadRequestException("Invalid JWT Token");
        }
    }
}