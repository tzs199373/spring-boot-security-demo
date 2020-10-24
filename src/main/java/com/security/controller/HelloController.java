package com.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "success";
    }
    @GetMapping("/admin/hello")
    public String hello2(){
        return "admin";
    }
    @GetMapping("/db/hello")
    public String hello3(){
        return "db";
    }
    @GetMapping("/user/hello")
    public String hello4(){
        return "user";
    }
}