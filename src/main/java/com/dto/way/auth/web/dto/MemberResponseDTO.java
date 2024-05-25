package com.dto.way.auth.web.dto;

import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.MemberStatus;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

public class MemberResponseDTO {

    @Getter
    @Setter
    public static class LoginMemberResponseDTO {

        private String name;
        private String nickname;
        private String email;
        private JwtToken jwtToken;
    }

    @Getter
    @Setter
    public static class MemberInfoResponseDTO {
        private Long memberId;
        private String name;
        private String nickname;
        private String profileImageUrl;
        private String introduce;
        private MemberStatus memberStatus;
        private String phoneNumber;
    }
}
