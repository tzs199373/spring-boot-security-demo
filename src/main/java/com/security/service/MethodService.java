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
