package com.ahmed.security.service;

import com.ahmed.security.exception.BadRequestException;
import com.ahmed.security.model.Role;
import com.ahmed.security.model.User;
import com.ahmed.security.repository.RoleRepository;
import com.ahmed.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User authenticateOAuth2User(OAuth2User oauthUser, String registrationId) {
        String username = getUsername(oauthUser, registrationId);
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isPresent()) {
            return optionalUser.get();
        }

        List<Role> roles = roleRepository.findByNameIn(
                List.of(com.ahmed.security.enums.Role.ROLE_USER, com.ahmed.security.enums.Role.ROLE_OAUTH2_USER)
        );
        return createUser(username, roles);
    }

    private User createUser(String username, List<Role> roles) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode("123456"));
        user.setRoles(roles);

        log.info("Creating user -> {}", user);
        return userRepository.save(user);
    }

    private String getUsername(OAuth2User oauthUser, String registrationId) {
        if(registrationId.equals("github")) {
            String oauth2Login = oauthUser.getAttribute("login");
            String oauth2Id = Objects.requireNonNull(oauthUser.getAttribute("id")).toString();
            return oauth2Login + oauth2Id;
        }
        if(registrationId.equals("google")) {
            String email = oauthUser.getAttribute("email");
            int atIndex = Objects.requireNonNull(email).indexOf('@');
            String oauth2Login = atIndex != -1 ? email.substring(0, atIndex) : email;
            String oauth2Id = Objects.requireNonNull(oauthUser.getAttribute("sub")).toString();
            return oauth2Login + oauth2Id;
        }
        return "";
    }
}
