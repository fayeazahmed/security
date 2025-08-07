package com.ahmed.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class AuthResponseDto {
    private Long id;
    private String username;
    private String jwtToken;
    private List<String> roles;
}
