package com.afarid.authenticationservice.controller;

import com.afarid.authenticationservice.dto.JwtAuthResponse;
import com.afarid.authenticationservice.dto.SignInRequest;
import com.afarid.authenticationservice.dto.SignUpRequest;
import com.afarid.authenticationservice.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    public ResponseEntity<JwtAuthResponse> signUp(@RequestBody SignUpRequest request){
        return new ResponseEntity<>(authenticationService.signUp(request), HttpStatus.CREATED);
    }

    @PostMapping("/sign-in")
    public ResponseEntity<JwtAuthResponse> signIn(@RequestBody SignInRequest request){
        return new ResponseEntity<>(authenticationService.signIn(request), HttpStatus.OK);
    }
}
