package com.burakkutbay.springsecurityjwtexample.controller;

import com.burakkutbay.springsecurityjwtexample.dto.UserDto;
import com.burakkutbay.springsecurityjwtexample.dto.UserRequest;
import com.burakkutbay.springsecurityjwtexample.dto.UserResponse;
import com.burakkutbay.springsecurityjwtexample.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;



    @PostMapping("/register")
    public ResponseEntity<UserResponse> save(@RequestBody UserDto userDto) {
        return ResponseEntity.ok(authenticationService.save(userDto));
    }

    @PostMapping("/login")
    public ResponseEntity<UserResponse> auth(@RequestBody UserRequest userRequest) {
        return ResponseEntity.ok(authenticationService.auth(userRequest));


    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    )
            throws IOException {
        authenticationService.refreshToken(request, response);
    }


}
