package dev.jlarsen.authserverdemo.repositories;

import dev.jlarsen.authserverdemo.models.UserEntity;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserEntity, Long> {

    UserEntity findByEmail(String email);
}
