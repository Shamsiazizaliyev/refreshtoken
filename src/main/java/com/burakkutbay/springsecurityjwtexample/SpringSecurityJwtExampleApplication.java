package com.burakkutbay.springsecurityjwtexample;

import com.burakkutbay.springsecurityjwtexample.enums.Permission;
import com.burakkutbay.springsecurityjwtexample.enums.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Set;



@SpringBootApplication
public class SpringSecurityJwtExampleApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtExampleApplication.class, args);
    }


    @Override
    public void run(String... args) throws Exception {

       // Role admin = Role.ADMIN;


        //Set<Permission> permissions = admin.getPermissions();


    }
}
