package com.medium_project.auth_api.repository;

import com.medium_project.auth_api.entity.ERole;
import com.medium_project.auth_api.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
