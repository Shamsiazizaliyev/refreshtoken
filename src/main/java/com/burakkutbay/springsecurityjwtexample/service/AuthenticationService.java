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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private  final TokenRepository tokenRepository;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public UserResponse save(UserDto userDto) {
        User user = User.builder()
                .username(userDto.getUsername())
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
}
