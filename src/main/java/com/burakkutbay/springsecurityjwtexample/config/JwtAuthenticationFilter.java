package com.burakkutbay.springsecurityjwtexample.config;

import com.burakkutbay.springsecurityjwtexample.repository.TokenRepository;
import com.burakkutbay.springsecurityjwtexample.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private  final TokenRepository tokenRepository;







    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String header = request.getHeader("Authorization");
        System.out.println("filter");


        final String jwt;
        final String username;
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            System.out.println("filterden cixdi");
            return;

        }



        jwt = header.substring(7);

        System.out.println(jwt);
        username = jwtService.findUsername(jwt);
        System.out.println("filter davam edir");

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null)//username ve movcud  hesab olmaqin yoxluyur

            {


            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            var isTokenValid=tokenRepository.findByToken(jwt)
                    .map(token -> !token.isExpired()&&!token.isRevoked())
                    .orElse(false);

            if (jwtService.tokenControl(jwt, userDetails) && isTokenValid) {


                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

         filterChain.doFilter(request, response);
    }
}
