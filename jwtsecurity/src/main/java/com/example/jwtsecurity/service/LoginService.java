package com.example.jwtsecurity.service;

import com.example.jwtsecurity.jwt.JwtUtil;
import com.example.jwtsecurity.model.LoginRequest;
import com.example.jwtsecurity.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class LoginService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    public Object authenticateUser(LoginRequest loginRequest){
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.username(),loginRequest.password()));
        }catch (AuthenticationException exception){
            Map<String,String> errorResponse = new HashMap<>();
            errorResponse.put("message","Bad Credentials");
            errorResponse.put("status", "Failed");
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assert authentication != null;
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtil.generateTokenFromUsername(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return new LoginResponse(jwtToken, userDetails.getUsername(), roles);
    }
}
