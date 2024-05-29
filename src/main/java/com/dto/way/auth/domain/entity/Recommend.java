package com.dto.way.auth.domain.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Recommend {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "recommend_id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "recommended_member", nullable = false)
    private Member recommendedMember;

    private Long memberId1;

    private Long memberId2;

    private Long memberId3;
}
