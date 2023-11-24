package com.afarid.authenticationservice.service;

import com.afarid.authenticationservice.dto.JwtAuthResponse;
import com.afarid.authenticationservice.dto.SignInRequest;
import com.afarid.authenticationservice.dto.SignUpRequest;
import com.afarid.authenticationservice.model.entities.User;
import com.afarid.authenticationservice.model.enums.Role;
import com.afarid.authenticationservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public JwtAuthResponse signUp(SignUpRequest request){

        User user = new User(
                null,
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                Role.USER,
                null,
                null
        );

        userService.saveUser(user);
        String token = jwtService.generateToken(user);
        log.info("Token: {}", token);

        return new JwtAuthResponse(token);
    }

    public JwtAuthResponse signIn(SignInRequest request){
        log.info("Entering signIn func from auth service");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new RuntimeException("Can't find user"));
        String token = jwtService.generateToken(user);

        return new JwtAuthResponse(token);
    }

}
