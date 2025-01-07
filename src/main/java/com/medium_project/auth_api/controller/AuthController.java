package com.medium_project.auth_api.controller;

import com.medium_project.auth_api.dto.request.LoginRequest;
import com.medium_project.auth_api.dto.request.RegisterRequest;
import com.medium_project.auth_api.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(path = "/api/v1")
public class AuthController {

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    AuthService authService;

    // REGISTER
    @PostMapping(path = "auth/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    // LOGIN
    @PostMapping("auth/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    // GET USER THAT CURRENTLY LOGIN WITH CERTAIN ROLE
    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Object> getUser() {
        return ResponseEntity.ok(authService.getUser());
    }
}
