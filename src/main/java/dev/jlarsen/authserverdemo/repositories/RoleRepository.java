package dev.jlarsen.authserverdemo.repositories;

import dev.jlarsen.authserverdemo.models.RoleEntity;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<RoleEntity, Integer> {

    RoleEntity findByRole(String role);
}
