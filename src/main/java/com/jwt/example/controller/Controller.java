package com.jwt.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class Controller {


    @GetMapping("/")
    public String hello(Principal principal){
    return "HEllo!!! ,"+ principal.getName();
}

@GetMapping("/user")
    public String user(){
        return "Hello, User!!";
}
    @GetMapping("/admin")
    public String admin(){
        return "Hello, admin!!";
    }


}
