package com.dto.way.auth.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public class MemberRequestDTO {

    @Getter
    @Setter
    public static class CreateMemberRequestDTO {

        @NotBlank(message = "이름은 필수 입력 값입니다.")
        private String name;

        @NotBlank(message = "이메일은 필수 입력 값입니다.")
        @Email(message = "이메일 형식에 맞지 않습니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 입력 값입니다.")
        // @Pattern(regexp="(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}",
        //        message = "비밀번호는 영문 대,소문자와 숫자, 특수기호가 적어도 1개 이상씩 포함된 8자 ~ 20자의 비밀번호여야 합니다.")
        // 비밀번호 암호화로 인한 pattern 처리 무효화
        private String password;

        @NotBlank(message = "비밀번호 확인은 필수 입력 값입니다.")
        private String passwordCheck;

        @NotBlank(message = "값을 입력해주세요.")
        @Pattern(regexp="^[A-Za-z0-9._]{4,10}$",
                message = "닉네임은 영문 대,소문자와 숫자, 특수문자(._)만 가능합니다. 길이는 4자 ~ 10자 입니다.")
        private String nickname;

        @NotBlank(message = "전화번호는 필수 입력 값입니다.")
        @Pattern(regexp = "^010-\\d{4}-\\d{4}$", message = "유효한 전화번호 형식이 아닙니다.")
        private String phoneNumber;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class LoginMemberRequestDTO {

        @NotBlank(message = "이메일은 필수 입력 값입니다.")
        @Email(message = "이메일 형식에 맞지 않습니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 입력 값입니다.")
        // @Pattern(regexp="(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}",
        //        message = "영문 대,소문자와 숫자, 특수기호가 적어도 1개 이상씩 포함된 8자 ~ 20자의 비밀번호를 입력해주세요.")
        // 비밀번호 암호화로 인한 pattern 처리 무효화
        private String password;
    }

    @Getter
    @Setter
    public static class CheckNicknameRequestDTO {

        @NotBlank(message = "값을 입력해주세요.")
        @Pattern(regexp="^[A-Za-z0-9._]{4,10}$",
                message = "닉네임은 영문 대,소문자와 숫자, 특수문자(._)만 가능합니다. 길이는 4자 ~ 10자 입니다.")
        private String nickname;

    }

    @Getter
    @Setter
    public static class CheckEmailRequestDTO {

        @NotBlank(message = "값을 입력해주세요.")
        @Email(message = "이메일 형식에 맞지 않습니다.")
        private String email;

    }
}
