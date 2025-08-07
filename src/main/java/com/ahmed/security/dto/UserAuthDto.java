package com.ahmed.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
public class UserAuthDto {
    private String username;
    private String password;
}
