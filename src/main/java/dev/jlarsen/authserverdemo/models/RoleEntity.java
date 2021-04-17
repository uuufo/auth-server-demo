package dev.jlarsen.authserverdemo.models;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "role_generator")
    private Long id;

    private String role;

    public RoleEntity() {
    }

    public RoleEntity(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
