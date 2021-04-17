package dev.jlarsen.authserverdemo.models;

import lombok.Data;

@Data
public class UserPrincipal {

    private String email;

    public UserPrincipal(String email) {
        this.email = email;
    }
}
