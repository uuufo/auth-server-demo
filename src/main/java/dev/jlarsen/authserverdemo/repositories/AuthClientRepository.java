package dev.jlarsen.authserverdemo.repositories;

import dev.jlarsen.authserverdemo.models.AuthClient;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthClientRepository extends CrudRepository<AuthClient, String> {

}
