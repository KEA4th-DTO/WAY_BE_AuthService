package com.dto.way.auth.domain.repository;

import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.Tag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TagRepository extends JpaRepository<Tag, Long> {

    @Query("SELECT t FROM Tag t WHERE t.taggedMember = :member")
    List<String> findByMember(Member member);
}
