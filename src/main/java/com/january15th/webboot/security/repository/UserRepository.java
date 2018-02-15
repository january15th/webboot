package com.january15th.webboot.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.january15th.webboot.security.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}