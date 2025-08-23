package com.ahmed.security.service;

import com.ahmed.security.config.UserDetailsImpl;
import com.ahmed.security.dto.AuthResponseDto;
import com.ahmed.security.dto.UserAuthDto;
import com.ahmed.security.exception.BadRequestException;
import com.ahmed.security.model.Role;
import com.ahmed.security.model.User;
import com.ahmed.security.repository.RoleRepository;
import com.ahmed.security.repository.UserRepository;
import com.ahmed.security.util.AuthUtils;
import com.ahmed.security.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtils jwtUtils;
    private final AuthUtils authUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResponseDto authenticate(UserAuthDto userAuthDto) {
        if (Boolean.FALSE.equals(userRepository.existsByUsername(userAuthDto.getUsername()))) {
            List<Role> roles = roleRepository.findByNameIn(
                    List.of(com.ahmed.security.enums.Role.ROLE_USER)
            );
            User user = createUser(userAuthDto.getUsername(), userAuthDto.getPassword(), roles);
            log.info("New user created: {}", user);
        }
        return getAuthenticationResponse(userAuthDto);
    }

    private User createUser(String username, String password, List<Role> roles) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(roles);

        return userRepository.save(user);
    }

    private AuthResponseDto getAuthenticationResponse(UserAuthDto userAuthDto) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(userAuthDto.getUsername(), userAuthDto.getPassword()));
        } catch (AuthenticationException ex) {
            log.error(ex.getMessage());
            throw new BadRequestException("Incorrect Credentials");
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUserDetails(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new AuthResponseDto(userDetails.getId(), userDetails.getUsername(), jwtToken, roles);
    }

    public User getAuthenticatedUser() {
        return authUtils.getAuthenticatedUser();
    }
}
