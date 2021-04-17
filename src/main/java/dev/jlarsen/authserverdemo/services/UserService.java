package dev.jlarsen.authserverdemo.services;

import dev.jlarsen.authserverdemo.models.UserEntity;
import dev.jlarsen.authserverdemo.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    public UserEntity getUser(String email) {
        return userRepository.findByEmail(email);
    }
}
