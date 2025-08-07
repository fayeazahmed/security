package com.ahmed.security.repository;

import com.ahmed.security.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    List<Role> findByNameIn(List<com.ahmed.security.enums.Role> roleNames);
}
