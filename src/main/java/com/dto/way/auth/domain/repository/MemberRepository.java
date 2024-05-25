package com.dto.way.auth.domain.repository;

import com.dto.way.auth.domain.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findById(Long id);

    Optional<Member> findByEmail(String email);

    Optional<Member> findByNickname(String nickname);

    boolean existsByNickname(String nickname);

    boolean existsByEmail(String email);
}
