package com.dto.way.auth.domain.repository;

import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.Recommend;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RecommendRepository extends JpaRepository<Recommend, Long> {

    @Query("SELECT r FROM Recommend r WHERE r.recommendedMember = :member")
    List<String> findByMember(Member member);
}
