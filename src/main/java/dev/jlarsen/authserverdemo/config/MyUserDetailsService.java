package dev.jlarsen.authserverdemo.config;

import dev.jlarsen.authserverdemo.models.AuthClient;
import dev.jlarsen.authserverdemo.models.RoleEntity;
import dev.jlarsen.authserverdemo.models.UserEntity;
import dev.jlarsen.authserverdemo.services.AuthService;
import dev.jlarsen.authserverdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
@Transactional
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    UserService userService;

    @Autowired
    AuthService authService;

    @Override
//    @Transactional
    public UserDetails loadUserByUsername(String username) {

        if (username.contains("@")) {
            return getUser(username);
        } else {
            return getClient(username);
        }
    }

//    private User getClient(String clientId) {
//        AuthClient authClient = authService.getClient(clientId);
//        List<GrantedAuthority> authorities =
//                new ArrayList<>(Collections.singletonList(new SimpleGrantedAuthority("ROLE_CLIENT")));
//        return new org.springframework.security.core.userdetails.User(clientId, "{noop}" + authClient.getClientSecret(),
//                true, true, true, true, authorities);
//    }

    private User getClient(String clientId) {
        AuthClient authClient = authService.getClient(clientId);
        List<GrantedAuthority> authorities =
                new ArrayList<>(Collections.singletonList(new SimpleGrantedAuthority("ROLE_CLIENT")));
        return new User(authClient.getClientId(), authClient.getClientSecret(),
                true, true, true, true, authorities);
    }

    private User getUser(String email) {
        UserEntity user = userService.getUser(email);
        List<GrantedAuthority> authorities = getUserAuthorities(user.getRoles());
        return new User(user.getEmail(), user.getPassword(),
                true, true, true, true, authorities);
    }

    private List<GrantedAuthority> getUserAuthorities(Set<RoleEntity> userRoles) {
        Set<GrantedAuthority> roles = new HashSet<>();
        for (RoleEntity role : userRoles) {
            roles.add(new SimpleGrantedAuthority("ROLE_" + role.getRole()));
        }
        return new ArrayList<>(roles);
    }
}