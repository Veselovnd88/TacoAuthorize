package ru.veselov.TacoAuthorize.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ru.veselov.TacoAuthorize.model.User;


public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
