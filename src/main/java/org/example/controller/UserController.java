package org.example.controller;

import org.example.model.User;
import org.example.repository.UserRepository;
import org.example.util.JWTUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;

    public UserController(JWTUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @GetMapping("/profile")
    public User getProfile(@RequestHeader("Authorization") String token){
        String string = token.substring(7);
        String email = jwtUtil.extractEmail(string);
        return userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("user Not Found"));
    }
}
