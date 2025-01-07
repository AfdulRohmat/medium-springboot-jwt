package com.medium_project.auth_api.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.medium_project.auth_api.entity.ERole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {

    private UUID id;
    private String username;
    private String email;

    @JsonProperty("is_verified")
    private Boolean isActive;

    private List<ERole> roles;
}