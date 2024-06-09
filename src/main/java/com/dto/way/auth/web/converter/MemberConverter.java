package com.dto.way.auth.web.converter;

import com.dto.way.auth.domain.entity.LoginType;
import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.MemberStatus;
import com.dto.way.auth.web.dto.JwtToken;
import com.dto.way.auth.web.dto.MemberResponseDTO;

import java.time.LocalDateTime;

import static com.dto.way.auth.domain.entity.MemberAuth.CLIENT;
import static com.dto.way.auth.web.dto.MemberRequestDTO.*;
import static com.dto.way.auth.web.dto.MemberResponseDTO.*;

public class MemberConverter {

    // 프로필 기본이미지 url
    public static final String DEFAULT_IMAGE = "https://way-bucket-s3.s3.ap-northeast-2.amazonaws.com/profile_image/default.jpg";

    /**
     * CreateMemberRequestDTO 를 기반으로 멤버 생성
     * 프로필 기본이미지 넣어줌
     * role은 CLIENT로 설정
     * 한줄 소개는 프로필 수정에서 처리
     */
    public static Member createMemberRequestDTOToMember(CreateMemberRequestDTO createMemberRequestDTO, String password) {
        return Member.builder()
                .name(createMemberRequestDTO.getName())
                .email(createMemberRequestDTO.getEmail())
                .password(password)
                .nickname(createMemberRequestDTO.getNickname())
                .phoneNumber(createMemberRequestDTO.getPhoneNumber())
                .memberStatus(MemberStatus.ACTIVATE)
                .profileImageUrl(DEFAULT_IMAGE)
                .createdAt(LocalDateTime.now())
                .memberAuth(CLIENT)
                .loginType(LoginType.GENERAL)
                .build();
    }
    public static LoginMemberResponseDTO toLoginMemberResponseDTO(Member loginMember, JwtToken  jwtToken) {
        return LoginMemberResponseDTO.builder()
                .name(loginMember.getName())
                .email(loginMember.getEmail())
                .nickname(loginMember.getNickname())
                .jwtToken(jwtToken)
                .build();
    }
}
