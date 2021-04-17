package dev.jlarsen.authserverdemo.models;

import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.Email;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Data
@Entity
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "user_generator")
    private Long id;

    private String name;

    @Column(unique = true)
    @Email
    private String email;

    @Column(length = 60)
    private String password;

    @OneToMany(cascade = CascadeType.PERSIST, fetch = FetchType.LAZY, mappedBy = "user")
    private List<AuthClient> clients;

    @ManyToMany(cascade = CascadeType.PERSIST)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles;

    public UserEntity(String name, String email, String password, Set<RoleEntity> roles) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    public UserEntity() {
    }
}
