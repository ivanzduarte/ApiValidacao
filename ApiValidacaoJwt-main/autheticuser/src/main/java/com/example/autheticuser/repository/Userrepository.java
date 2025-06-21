package com.example.autheticuser.repository;

import com.example.autheticuser.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface Userrepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}