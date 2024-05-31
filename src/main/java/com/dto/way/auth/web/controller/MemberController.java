package com.dto.way.auth.web.controller;

import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.service.MemberService;
import com.dto.way.auth.web.dto.JwtToken;
import com.dto.way.auth.web.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import static com.dto.way.auth.web.dto.MemberRequestDTO.*;
import static com.dto.way.auth.web.dto.MemberResponseDTO.*;
import static com.dto.way.auth.web.response.code.status.SuccessStatus.*;
import static com.dto.way.auth.web.response.code.status.ErrorStatus.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth-service")
public class MemberController {

    private final MemberService memberService;

    // 회원가입
    @Operation(summary = "회원가입 API", description = "이름, 이메일, 비밀번호, 비밀번호 확인, 닉네임, 전화번호를 request body에 넣어주세요. 필드 값에 따라 정해진 형식에 맞게 넣어야 올바른 응답이 전송됩니다.")
    @PostMapping("/signup")
    public ApiResponse<CreateMemberRequestDTO> signUp(@Valid @RequestBody CreateMemberRequestDTO createMemberRequestDTO) {

        String result = memberService.createMember(createMemberRequestDTO);

        if (result.equals(MEMBER_SIGNUP.getCode())) { // 회원가입에 성공한 경우
            String nickname = createMemberRequestDTO.getNickname();
            log.info("member nickname = {}", nickname);
            Member member = memberService.findMemberByNickname(nickname);
            memberService.initTagAndRecommend(member);
            return ApiResponse.of(MEMBER_SIGNUP, createMemberRequestDTO);
        }

        else if (result.equals(MEMBER_EMAIL_DUPLICATED.getCode())) { // 이메일 중복인 경우
            return ApiResponse.onFailure(MEMBER_EMAIL_DUPLICATED.getCode(), MEMBER_EMAIL_DUPLICATED.getMessage(), createMemberRequestDTO);
        }

        else if (result.equals(MEMBER_NICKNAME_DUPLICATED.getCode())) { // 닉네임 중복인 경우
            return ApiResponse.onFailure(MEMBER_NICKNAME_DUPLICATED.getCode(), MEMBER_NICKNAME_DUPLICATED.getMessage(), createMemberRequestDTO);
        }

        else { // 비밀번호가 일치하지 않는 경우
            return ApiResponse.onFailure(MEMBER_PASSWORD_NOT_MATCHED.getCode(), MEMBER_PASSWORD_NOT_MATCHED.getMessage(), createMemberRequestDTO);
        }
    }

    // 로그인
    @Operation(summary = "로그인 API", description = "이메일, 비밀번호를 request body에 넣어주세요. 필드 값에 따라 정해진 형식에 맞게 넣어야 올바른 응답이 전송됩니다.")
    @PostMapping("/login")
    public ApiResponse<LoginMemberResponseDTO> login(@Valid @RequestBody LoginMemberRequestDTO loginMemberRequestDTO) {

        JwtToken jwtToken = memberService.login(loginMemberRequestDTO);

        LoginMemberResponseDTO loginMemberResponseDTO = new LoginMemberResponseDTO();

        if (jwtToken.getGrantType().equals(MEMBER_LOGIN_FAILED.getCode())) {
            return ApiResponse.onFailure(MEMBER_LOGIN_FAILED.getCode(), MEMBER_LOGIN_FAILED.getMessage(), loginMemberResponseDTO);
        } else {
            Member loginMember = memberService.findMemberByEmail(loginMemberRequestDTO.getEmail());
            loginMemberResponseDTO.setName(loginMember.getName());
            loginMemberResponseDTO.setEmail(loginMember.getEmail());
            loginMemberResponseDTO.setNickname(loginMember.getNickname());
            loginMemberResponseDTO.setJwtToken(jwtToken);

            return ApiResponse.of(MEMBER_LOGIN, loginMemberResponseDTO);
        }
    }

    // 로그아웃
    @Operation(summary = "로그아웃 API", description = "로그아웃 할 사용자의 jwt token 값을 request body에 넣어주세요. 클라이언트에서 token 값을 삭제해야 합니다.")
    @PostMapping("/logout")
    public ApiResponse<JwtToken> logout(@RequestBody JwtToken jwtToken) {
        memberService.logout(jwtToken);

        return ApiResponse.of(MEMBER_LOGOUT, jwtToken);
    }

    // refresh token을 이용한 토큰 재발급
    @Operation(summary = "토큰 재발급 API", description = "access token이 만료된 경우 refresh token을 이용하여 jwt token을 재발급 받는 API입니다. jwt token을 request body에 넣어주세요.")
    @PostMapping("/recreate-token")
    public ApiResponse<JwtToken> recreateToken(@RequestBody JwtToken jwtToken) {
        String refreshToken = jwtToken.getRefreshToken();
        JwtToken newJwtToken = memberService.checkRefreshTokenIsValid(refreshToken);
        if (newJwtToken.getAccessToken() == null) {
            return ApiResponse.onFailure(MEMBER_RECREATE_TOKEN_FAILED.getCode(), MEMBER_RECREATE_TOKEN_FAILED.getMessage(), newJwtToken);
        } else {
            return ApiResponse.of(MEMBER_RECREATE_TOKEN, newJwtToken);
        }
    }

    // 닉네임 중복 검사
    @Operation(summary = "닉네임 중복 검사 API", description = "중복 검사 하려는 nickname을 request body에 넣어주세요.")
    @PostMapping("/check-nickname")
    public ApiResponse<String> checkNickname(@Valid @RequestBody CheckNicknameRequestDTO checkNicknameRequestDTO) {
        if (memberService.checkNicknameDuplication(checkNicknameRequestDTO.getNickname())) {
            return ApiResponse.onFailure(MEMBER_NICKNAME_DUPLICATED.getCode(), MEMBER_NICKNAME_DUPLICATED.getMessage(), "이미 사용 중인 닉네임 입니다.");
        } else {
            return ApiResponse.of(_OK, "사용 가능한 닉네임 입니다.");
        }
    }

    // 이메일 중복 검사
    @Operation(summary = "이메일 중복 검사 API", description = "중복 검사 하려는 email을 request body에 넣어주세요.")
    @PostMapping("/check-email")
    public ApiResponse<String> checkEmail(@Valid @RequestBody CheckEmailRequestDTO checkEmailRequestDTO) {
        if (memberService.checkEmailDuplication(checkEmailRequestDTO.getEmail())) {
            return ApiResponse.onFailure(MEMBER_EMAIL_DUPLICATED.getCode(), MEMBER_EMAIL_DUPLICATED.getMessage(), "이미 사용 중인 이메일 입니다.");
        } else {
            return ApiResponse.of(_OK, "사용 가능한 이메일 입니다.");
        }
    }

}
