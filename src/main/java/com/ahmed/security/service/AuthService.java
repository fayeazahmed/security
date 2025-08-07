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

import java.util.List;
import java.util.stream.Collectors;

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

    public AuthResponseDto authenticate(UserAuthDto userAuthDto) {
        if (!userRepository.existsByUsername(userAuthDto.getUsername())) {
            User user = new User();
            user.setUsername(userAuthDto.getUsername());
            user.setPassword(passwordEncoder.encode(userAuthDto.getPassword()));
            List<Role> roles = roleRepository.findByNameIn(
                    List.of(com.ahmed.security.enums.Role.ROLE_USER)
            );
            user.setRoles(roles);

            userRepository.save(user);
            log.info("New user created: {}", user);
        }
        return getAuthenticationResponse(userAuthDto);
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
                .collect(Collectors.toList());

        return new AuthResponseDto(userDetails.getId(), userDetails.getUsername(), jwtToken, roles);
    }

    public User getAuthenticatedUser() {
        return authUtils.getAuthenticatedUser();
    }
}
