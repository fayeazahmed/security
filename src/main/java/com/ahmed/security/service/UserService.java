package com.ahmed.security.service;

import com.ahmed.security.model.Role;
import com.ahmed.security.model.User;
import com.ahmed.security.repository.RoleRepository;
import com.ahmed.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public User getUserFromOAuth2User(DefaultOAuth2User oauth2User) {
        String githubUsername = oauth2User.getAttributes().get("login").toString();
        String githubId = oauth2User.getAttributes().get("id").toString();

        Optional<User> optionalUser = userRepository.findByUsername(githubUsername);
        if(optionalUser.isPresent()) {
            User user = optionalUser.get();
            if(user.getGithubId() == null) {
                return createFromOAuth2User(githubUsername, githubId, true);
            }
            if(user.getGithubId().equals(githubId)) {
                return user;
            }
            return getUser(githubUsername, githubId);
        } else {
            return createFromOAuth2User(githubUsername, githubId, false);
        }
    }

    private User getUser(String githubUsername, String githubId) {
        return createFromOAuth2User(githubUsername, githubId, true);
    }

    private User createFromOAuth2User(String githubUsername, String githubId, boolean userExists) {
        List<Role> roles = roleRepository.findByNameIn(
                List.of(com.ahmed.security.enums.Role.ROLE_USER)
        );
        String username = userExists ? githubUsername + "_" + githubId : githubUsername;

        return User.builder()
                .username(username)
                .password("")
                .githubId(githubId)
                .roles(roles)
                .build();
    }
}
