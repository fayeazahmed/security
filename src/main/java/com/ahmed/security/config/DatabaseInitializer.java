package com.ahmed.security.config;

import com.ahmed.security.model.Role;
import com.ahmed.security.model.User;
import com.ahmed.security.repository.RoleRepository;
import com.ahmed.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DatabaseInitializer implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void run(String... args) {
        if (roleRepository.findAll().isEmpty()) {
            Role roleAdmin = new Role();
            roleAdmin.setName(com.ahmed.security.enums.Role.ROLE_ADMIN);
            Role roleUser = new Role();
            roleUser.setName(com.ahmed.security.enums.Role.ROLE_USER);
            roleRepository.saveAll(List.of(roleAdmin, roleUser));

            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin"));
            admin.setRoles(roleRepository.findByNameIn(
                    List.of(com.ahmed.security.enums.Role.ROLE_ADMIN, com.ahmed.security.enums.Role.ROLE_USER)
            ));

            userRepository.save(admin);
        }
    }
}
