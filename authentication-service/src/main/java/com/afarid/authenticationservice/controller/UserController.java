package com.afarid.authenticationservice.controller;

import com.afarid.authenticationservice.model.entities.User;
import com.afarid.authenticationservice.repository.UserRepository;
import com.afarid.authenticationservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    @GetMapping("/{userId}")
    public ResponseEntity<User> getUser(@PathVariable("userId") Integer id){

        return new ResponseEntity<>(userService.getUser(id), HttpStatus.OK);
    }
}
