package com.medium_project.auth_api.service;

import com.medium_project.auth_api.config.security.jwt.JwtUtils;
import com.medium_project.auth_api.config.security.services.UserDetailsImpl;
import com.medium_project.auth_api.dto.request.LoginRequest;
import com.medium_project.auth_api.dto.request.RegisterRequest;
import com.medium_project.auth_api.dto.response.LoginResponse;
import com.medium_project.auth_api.dto.response.RegisterUserResponse;
import com.medium_project.auth_api.dto.response.UserResponse;
import com.medium_project.auth_api.entity.ERole;
import com.medium_project.auth_api.entity.Role;
import com.medium_project.auth_api.entity.User;
import com.medium_project.auth_api.repository.RoleRepository;
import com.medium_project.auth_api.repository.UserRepository;
import com.medium_project.auth_api.utils.Response;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthService {


    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder encoder,
            AuthenticationManager authenticationManager,
            JwtUtils jwtUtils
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    UserRepository userRepository;

    RoleRepository roleRepository;

    PasswordEncoder encoder;

    AuthenticationManager authenticationManager;

    JwtUtils jwtUtils;

    // Register Function
    @Transactional
    public Response<Object> register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already registered");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already registered");
        }

        // generate bcrypt password
        String hashedPassword = encoder.encode(request.getPassword());

        // Define User instance, then set new value
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(hashedPassword);
        user.setIsActive(true);

        // Set default role to ROLE_ADMIN
        Role adminRole = new Role(ERole.ROLE_ADMIN); // Create the Role instance
        roleRepository.save(adminRole); // Save it to the database

        Set<Role> roles = new HashSet<>();
        roles.add(adminRole); // Add the persisted Role

        user.setRoles(roles);

        // save user
        userRepository.save(user);

        // return response DTO
        RegisterUserResponse registerUserResponse = RegisterUserResponse.builder()
                .name(user.getUsername())
                .email(user.getEmail())
                .build();

        return Response.builder()
                .responseCode(200)
                .responseMessage("SUCCESS")
                .data(registerUserResponse)
                .build();
    }

    // Login Function
    @Transactional
    public Response<Object> login(LoginRequest request) {

        // Check if User by Email exist. if not throw error
        userRepository.findFirstByEmail(request.getEmail()).orElseThrow(() -> new RuntimeException("User not found. Please register first"));


        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse loginResponse = LoginResponse.builder()
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .accessToken(jwt)
                .tokenType("Bearer")
                .build();

        return Response.builder()
                .responseCode(200)
                .responseMessage("SUCCESS")
                .data(loginResponse)
                .build();
    }

    // GET USER THAT CURRENTLY LOGIN
    @Transactional
    public Response<Object> getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        UUID userId = userDetails.getId();

        User user = userRepository.findById(userId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found !"));

        UserResponse userResponse = UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .isActive(user.getIsActive())
                .roles(user.getRoles().stream().map(Role::getName).toList())
                .build();

        return Response.builder()
                .responseCode(200)
                .responseMessage("SUCCESS")
                .data(userResponse)
                .build();
    }
}
