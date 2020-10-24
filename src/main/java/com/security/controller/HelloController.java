package com.security.controller;

import com.security.service.MethodService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @Autowired
    MethodService methodService;

    @GetMapping("/hello")
    public String hello() {
        return methodService.admin();
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
