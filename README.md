# SpringSecurity入门
本项目是基于内存认证，供初学者学习，基于数据库认证可参考spring-boot-security-demo-v2
## 小试牛刀

添加依赖

```xml
<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
```

准备一个访问接口

```java
package com.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
```

配置一个用户

```properties
spring.security.user.name=guest
spring.security.user.password=123456
spring.security.user.roles=user
```

启动项目访问：http://localhost:8080/hello	项目自动跳转到由spring security提供的页面

输入账号密码后，再次访问http://localhost:8080/hello

## 基于内存的认证

```java
package com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        //密码加密，使用NoOpPasswordEncoder即不加密
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //root有ADMIN和DBA角色，admin有ADMIN和USER角色，cc有USER角色

        auth.inMemoryAuthentication()
                .withUser("root").password("123").roles("ADMIN","DBA")
                .and()
                .withUser("admin").password("123").roles("ADMIN","USER")
                .and()
                .withUser("user").password("123").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //url为/admin/的需要admin角色，/user/的需要admin或者user，/db/的需要admin和dba角色

        http.authorizeRequests()
                .antMatchers("/admin/**")
                .hasRole("ADMIN")
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasAnyRole('ADMIN') and  hasRole('DBA')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().permitAll()//允许登录
                .and()
                .csrf().disable();//关闭跨域
    }

}

```

## 路径拦截

```java
package com.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
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

```

说明：访问以上路径会跳转到登录页面，使用不同角色的账号登陆后，再次访问各自允许的url路径会成功，而不允许的会失败。

## 方法拦截

除了url路径拦截校验，security还支持方法注解拦截

首先添加配置支持

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
//prePostEnabled=true会解锁@PreAuthorize和@PostAuthorize两个注解
//@PreAuthorize注解会在方法执行前进行验证，而@PostAuthorize 注解在方法执行后进行验证。
//securedEnabled=true会解锁@Secured注解。
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
]
```

添加方法

```java
package com.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {
    @Secured("ROLE_ADMIN")//访问此方法需要ADMIN角色
    public String admin() {return "hello admin";}
    @PreAuthorize("hasRole('ADMIN') and hasRole('DBA')")  //访问此方法需要ADMIN且DBA
    public String dba() {
        return "hello dba";
    }
    @PreAuthorize("hasAnyRole('ADMIN','DBA','USER')")    //三个都行
    public String user() {
        return "hello user";
    }
}
```

改造HelloController中hello方法，调用MethodService中添加了拦截的方法

```java
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
}

```
可以发现，之前hello路径，任何角色登陆后都可以访问，改造后需要admin角色才行。当然controller方法上直接使用该类注解也是可以的


## 自定义登录页面及成功失败处理

```java
package com.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        //密码加密，使用NoOpPasswordEncoder即不加密
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //root有ADMIN和DBA角色，admin有ADMIN和USER角色，cc有USER角色

        auth.inMemoryAuthentication()
                .withUser("root").password("123").roles("ADMIN","DBA")
                .and()
                .withUser("admin").password("123").roles("ADMIN","USER")
                .and()
                .withUser("user").password("123").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //url为/admin/的需要admin角色，/user/的需要admin或者user，/db/的需要admin和dba角色

        http.authorizeRequests()
                .antMatchers("/admin/**")
                .hasRole("ADMIN")
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasAnyRole('ADMIN') and  hasRole('DBA')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().permitAll()
                .loginPage("/login.html") //自定义登陆页面
                .loginProcessingUrl("/mylogin")//自定义登陆页面的登陆action

                .successHandler(new AuthenticationSuccessHandler() {//登陆成功后
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        Authentication auth)
                            throws IOException {
                        Object principal = auth.getPrincipal();
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(200);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", principal);
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })

                .failureHandler(new AuthenticationFailureHandler() {//登陆失败后
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        AuthenticationException e)
                            throws IOException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(401);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 401);
                        if (e instanceof LockedException) {
                            map.put("msg", "账户被锁定，登录失败!");
                        } else if (e instanceof BadCredentialsException) {
                            map.put("msg", "账户名或密码输入错误，登录失败!");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "账户被禁用，登录失败!");
                        } else if (e instanceof AccountExpiredException) {
                            map.put("msg", "账户已过期，登录失败!");
                        } else if (e instanceof CredentialsExpiredException) {
                            map.put("msg", "密码已过期，登录失败!");
                        } else {
                            map.put("msg", "登录失败!");
                        }
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()

                .logout()//开启注销登陆
                .logoutUrl("/logout")//注销登陆请求url
                .clearAuthentication(true)//清除身份信息
                .invalidateHttpSession(true)//session失效
                .addLogoutHandler(new LogoutHandler() {//注销处理
                    @Override
                    public void logout(HttpServletRequest req,
                                       HttpServletResponse resp,
                                       Authentication auth) {

                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { //注销成功处理
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req,
                                                HttpServletResponse resp,
                                                Authentication auth)
                            throws IOException {
                        resp.sendRedirect("/login.html");//跳转到自定义登陆页面
                    }
                })
                .and()

                .csrf().disable();
    }

}

```

