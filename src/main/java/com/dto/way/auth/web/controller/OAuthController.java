package com.dto.way.auth.web.controller;

import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.service.MemberService;
import com.dto.way.auth.domain.service.OAuthService;
import com.dto.way.auth.global.OAuthProperties;
import com.dto.way.auth.web.dto.JwtToken;
import com.dto.way.auth.web.dto.KakaoInfo;
import com.dto.way.auth.web.response.ApiResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.dto.way.auth.web.dto.MemberRequestDTO.*;
import static com.dto.way.auth.web.response.code.status.SuccessStatus.MEMBER_LOGIN;

@Controller
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class OAuthController {

    private final OAuthService oAuthService;
    private final MemberService memberService;
    private final OAuthProperties oAuthProperties;

    /**
     * 카카오 로그인 요청
     * return redirect url
     */
    @GetMapping("/kakao")
    public String kakaoConnect() {
        StringBuffer url = new StringBuffer();
        url.append("https://kauth.kakao.com/oauth/authorize?");
        url.append("client_id=" + oAuthProperties.getKakaoClientId());
        url.append("&redirect_uri=" + oAuthProperties.getKakaoRedirectUri());
        url.append("&response_type=code");
        return "redirect:" + url;
    }

    /**
     * 카카오 로그인 콜백
     * @return
     */
    @GetMapping("/kakao/callback")
    public ApiResponse<JwtToken> kakaoCallback(@RequestParam String code, HttpSession session) {
        // STEP1: 인가코드 받기

        // STEP2: 인가코드를 기반으로 토큰(Access Token) 발급
        String accessToken;
        try {
            accessToken = oAuthService.getAccessToken(code);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        // STEP3: 토큰을 통해 사용자 정보 조회
        KakaoInfo kakaoInfo;
        try {
            kakaoInfo = oAuthService.getKakaoInfo(accessToken);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        // STEP4: 카카오 사용자 정보 확인
        Member kakaoMember = oAuthService.ifNeedKakaoInfo(kakaoInfo);

        String email = kakaoMember.getEmail();
        String password = kakaoMember.getPassword();

        // STEP5: 강제 로그인
        LoginMemberRequestDTO loginMemberRequestDTO = new LoginMemberRequestDTO(email, password);
        JwtToken jwtToken = memberService.login(loginMemberRequestDTO);

        // STEP5: 강제 로그인
        // 세션에 회원 정보 저장 & 세션 유지 시간 설정
        session.setAttribute("loginMember", kakaoMember);
        // session.setMaxInactiveInterval( ) : 세션 타임아웃을 설정하는 메서드
        // 로그인 유지 시간 설정 (1800초 == 30분)
        session.setMaxInactiveInterval(60 * 30);
        // 로그아웃 시 사용할 카카오토큰 추가
        session.setAttribute("kakaoToken", accessToken);

        return ApiResponse.of(MEMBER_LOGIN, jwtToken);
    }

    /**
     * 카카오 로그아웃
     * @return
     */
    @GetMapping("/kakao/logout")
    public String kakaoLogout(HttpSession session) {
        String accessToken = (String) session.getAttribute("kakaoToken");

        if (accessToken != null && !"".equals(accessToken)) {
            try {
                oAuthService.kakaoDisconnect(accessToken);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            session.removeAttribute("kakaoToken");
            session.removeAttribute("loginMember");
        } else {
            return "로그아웃 실패: accessToken이 null입니다.";
        }

        return "로그아웃 성공";
    }
}
