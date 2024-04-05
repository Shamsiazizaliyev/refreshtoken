package com.burakkutbay.springsecurityjwtexample.dto;

import com.burakkutbay.springsecurityjwtexample.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

    private String mail;
    private String name;
    private String surName;
    private String username;
    private String password;


}
