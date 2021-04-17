package dev.jlarsen.authserverdemo.repositories;

import dev.jlarsen.authserverdemo.models.JwkEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface JwkRepository extends CrudRepository<JwkEntity, Integer> {

}
