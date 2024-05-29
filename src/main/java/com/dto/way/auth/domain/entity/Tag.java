package com.dto.way.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Tag {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "tag_id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "tagged_member", nullable = false)
    private Member taggedMember;

    private String wayTag1;

    private String wayTag2;

    private String wayTag3;
}
