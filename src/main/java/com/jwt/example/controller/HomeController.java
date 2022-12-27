package com.jwt.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HomeController {

    @GetMapping("/use")
    public String home() {
        return "Hello, World!";
    }


    @GetMapping("/adm")
    public String admin() {
        return "Hello, Admin!";
    }
}