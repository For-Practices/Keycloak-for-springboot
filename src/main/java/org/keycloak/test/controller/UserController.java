package org.keycloak.test.controller;

import org.keycloak.test.model.User;
import org.keycloak.test.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;


@CrossOrigin
@RestController
@RequestMapping("/api/v1/users/")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/signUp")
    public User signUp(@RequestBody User user){
        return userRepository.save(user);
    }

   /* @GetMapping(value = "/signIn")
    @ResponseBody
    public User signIn(@RequestParam Map<String,String> allParams){

    }*/
}
