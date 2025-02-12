package com.burakkutbay.springsecurityjwtexample.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")

public class AdminController {



    @GetMapping("test")
    @PreAuthorize("hasRole('ADMIN')")
    public String get() {
        return "GET:: admin controller";
    }


    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public String post() {
        return "POST:: admin controller";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public String put() {
        return "PUT:: admin controller";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public String delete() {
        return "DELETE:: admin controller";
    }
}