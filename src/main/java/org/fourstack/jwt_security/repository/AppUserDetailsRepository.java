package org.fourstack.jwt_security.repository;

import org.fourstack.jwt_security.entity.AppUserDetails;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserDetailsRepository extends MongoRepository<AppUserDetails, String> {

  Optional<AppUserDetails> findByEmailIgnoreCase(String email);

  boolean existsByEmailIgnoreCase(String email);
}
