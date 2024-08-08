package com.example.jwtsecurity.model;

import java.util.List;

public record LoginResponse(String jwtToken, String username, List<String> roles) {
}
