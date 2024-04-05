package com.burakkutbay.springsecurityjwtexample.service;

import com.burakkutbay.springsecurityjwtexample.dto.UserDto;
import com.burakkutbay.springsecurityjwtexample.dto.UserRequest;
import com.burakkutbay.springsecurityjwtexample.dto.UserResponse;
import com.burakkutbay.springsecurityjwtexample.entity.User;
import com.burakkutbay.springsecurityjwtexample.enums.Role;
import com.burakkutbay.springsecurityjwtexample.repository.TokenRepository;
import com.burakkutbay.springsecurityjwtexample.repository.UserRepository;
import com.burakkutbay.springsecurityjwtexample.token.Token;
import com.burakkutbay.springsecurityjwtexample.token.TokenType;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private  final TokenRepository tokenRepository;

    private final JwtService jwtService;

    @Autowired
    private Otp otpUtil;
    @Autowired
    private MailService emailUtil;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public UserResponse save(UserDto userDto) {

        String otp = otpUtil.generateOtp();
        try {
            emailUtil.sendOtpEmail(userDto.getMail(), otp);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send otp please try again");
        }
        User user = User.builder()
                .username(userDto.getUsername())
                .otp(otp)
                .otpGeneratedTime(LocalDateTime.now())
                .email(userDto.getMail())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .name(userDto.getName())
                .surName(userDto.getSurName())
                .role(Role.USER).build();
       var saveUser= userRepository.save(user);
        var token = jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
      saveUserToken(saveUser, token);

        return UserResponse.builder().
                accessToken(token)
                        .refreshToken(refreshToken)
                .build();


    }



    public UserResponse auth(UserRequest userRequest) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequest.getUsername(), userRequest.getPassword()));
        User user = userRepository.findByUsername(userRequest.getUsername()).orElseThrow();
        String token = jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,token);

        return UserResponse.builder().accessToken(token).refreshToken(refreshToken)
                .build();

    }


    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);

    }
    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);

        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            final String refreshToken;
            final String username;
            if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
                return;
            }
             refreshToken = authHeader.substring(7);
        username = jwtService.findUsername(refreshToken);
            if (username != null) {

                var user = this.userRepository.findByUsername(username)
                        .orElseThrow();
                if (jwtService.tokenControl(refreshToken, user)) {
                    var accessToken = jwtService.generateToken(user);
                    revokeAllUserTokens(user);
                    saveUserToken(user, accessToken);
                    var authResponse = UserResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
    }


    public String verifyAccount(String email, String otp) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));
        if (user.getOtp().equals(otp) ) {
            user.setActive(true);
            userRepository.save(user);
            return "OTP verified you can login";
        }
        return "Please regenerate otp and try again";

    }

    public String regenerateOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));
        String otp = otpUtil.generateOtp();
        try {
            emailUtil.sendOtpEmail(email, otp);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send otp please try again");
        }
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userRepository.save(user);
        return "Email sent... please verify account within 1 minute";
    }

    public String forgotPassword(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));

        try {
            emailUtil.sendSetPasswordEmail(email);
        } catch (MessagingException e) {
            throw new RuntimeException("Unable to send set password email please try again");


        }
        return "Please check your email to set new password to your account";

    }

    public String setPassword(String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));

        user.setPassword(newPassword);
        System.out.println(newPassword);
        userRepository.save(user);
        return "New Password set succesfully login with new password";

    }
}
