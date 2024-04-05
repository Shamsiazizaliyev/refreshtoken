package com.burakkutbay.springsecurityjwtexample.controller;

import com.burakkutbay.springsecurityjwtexample.dto.UserDto;
import com.burakkutbay.springsecurityjwtexample.dto.UserRequest;
import com.burakkutbay.springsecurityjwtexample.dto.UserResponse;
import com.burakkutbay.springsecurityjwtexample.entity.User;
import com.burakkutbay.springsecurityjwtexample.service.AuthenticationService;
import com.burakkutbay.springsecurityjwtexample.service.MailService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    private MailService service;


    @GetMapping("/test")
    public String test(){


        return "test";
    }

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






   /* @GetMapping("/normal")
    public ResponseEntity<String> sendNormalMail(){
        service.sendMail("samsiazizaliyev@gmail.com", "Salaamm");
        return ResponseEntity.ok("Success");

    }
*/





    @PutMapping("/verify-account")
    public ResponseEntity<String> verifyAccount(@RequestParam String email,
                                                @RequestParam String otp) {
        return new ResponseEntity<>(authenticationService.verifyAccount(email, otp), HttpStatus.OK);
    }


    @PutMapping("/regenerate-otp")
    public ResponseEntity<String> regenerateOtp(@RequestParam String email) {


        return new ResponseEntity<>(authenticationService.regenerateOtp(email), HttpStatus.OK);
    }

    @PutMapping("/forget-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email) {

        return new ResponseEntity<>(authenticationService.forgotPassword(email), HttpStatus.OK);
    }

    @PutMapping("/set-password")
    public ResponseEntity<String>setPassword(@RequestParam String email,@RequestParam String newPassword) {

        System.out.println("set password");
        return new ResponseEntity<>(authenticationService.setPassword(email,newPassword), HttpStatus.OK);
    }






}
