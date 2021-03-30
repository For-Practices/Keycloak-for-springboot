package org.keycloak.test.controller;

import org.keycloak.test.model.User;
import org.keycloak.test.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;
import java.util.List;


@CrossOrigin
@RestController
@RequestMapping("/api/v1/users/")

public class UserController {
    @Autowired
    private UserRepository userRepository;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/signUp")
    @RolesAllowed("user")
    public User save(@RequestBody User user){
        System.out.println("post");
        return userRepository.save(user);
    }

    @GetMapping("/signIn")
    @RolesAllowed("user")
    public List<User> findAll(){
        System.out.println("get");
        return userRepository.findAll();
    }
}
