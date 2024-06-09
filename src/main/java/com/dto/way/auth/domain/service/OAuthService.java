package com.dto.way.auth.domain.service;

import com.dto.way.auth.domain.entity.LoginType;
import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.MemberStatus;
import com.dto.way.auth.global.OAuthProperties;
import com.dto.way.auth.web.dto.KakaoInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.UUID;

import static com.dto.way.auth.domain.entity.MemberAuth.CLIENT;
import static com.dto.way.auth.web.converter.MemberConverter.DEFAULT_IMAGE;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthService {

    private final MemberService memberService;
    private final OAuthProperties oAuthProperties;
    private final ObjectMapper objectMapper;

    public String getAccessToken(String code) throws JsonProcessingException {
        // HTTP Header 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // HTTP Body 생성
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", oAuthProperties.getKakaoClientId());
        body.add("redirect_uri", oAuthProperties.getKakaoRedirectUri());
        body.add("code", code);
        body.add("client_secret", oAuthProperties.getKakaoClientSecret());

        // HTTP 요청 보내기
        HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = new HttpEntity<>(body, headers);
        RestTemplate rt = new RestTemplate();
        ResponseEntity<String> response = rt.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                kakaoTokenRequest,
                String.class
        );

        // HTTP 응답 (JSON) -> 액세스 토큰 파싱
        String responseBody = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(responseBody);

        return jsonNode.get("access_token").asText();
    }

    public KakaoInfo getKakaoInfo(String accessToken) throws JsonProcessingException {
        // HTTP Header 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // HTTP 요청 보내기
        HttpEntity<MultiValueMap<String, String>> kakaoUserInfoRequest = new HttpEntity<>(headers);
        RestTemplate rt = new RestTemplate();
        ResponseEntity<String> response = rt.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.POST,
                kakaoUserInfoRequest,
                String.class
        );

        // responseBody에 있는 정보 꺼내기
        String responseBody = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(responseBody);

        Long id = jsonNode.get("id").asLong();
        String email = jsonNode.get("kakao_account").get("email").asText();
        String nickname = jsonNode.get("properties")
                .get("nickname").asText();

        return new KakaoInfo(nickname, email);
    }

    public Member ifNeedKakaoInfo(KakaoInfo kakaoInfo) {
        String kakaoEmail = kakaoInfo.getEmail();
        Member kakaoMember = memberService.findMemberByEmail(kakaoEmail);

        if (kakaoMember != null) {
            return kakaoMember;
        } else {
            String tempName = UUID.randomUUID().toString();
            String tempNickname = UUID.randomUUID().toString();
            String tempPassword = UUID.randomUUID().toString();
            String tempPhoneNumber = UUID.randomUUID().toString();

            return Member.builder()
                    .name(tempName)
                    .email(kakaoEmail)
                    .password(tempPassword)
                    .nickname(tempNickname)
                    .phoneNumber(tempPhoneNumber)
                    .memberStatus(MemberStatus.ACTIVATE)
                    .profileImageUrl(DEFAULT_IMAGE)
                    .createdAt(LocalDateTime.now())
                    .memberAuth(CLIENT)
                    .loginType(LoginType.KAKAO)
                    .build();
        }
    }

    public void kakaoDisconnect(String accessToken) throws JsonProcessingException {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + accessToken);
            headers.add("Content-type", "application/x-www-form-urlencoded");

            HttpEntity<MultiValueMap<String, String>> kakaoLogoutRequest = new HttpEntity<>(headers);
            RestTemplate rt = new RestTemplate();
            ResponseEntity<String> response = rt.exchange(
                    "https://kapi.kakao.com/v1/user/logout",
                    HttpMethod.POST,
                    kakaoLogoutRequest,
                    String.class
            );

            String responseBody = response.getBody();
            JsonNode jsonNode = objectMapper.readTree(responseBody);

            Long id = jsonNode.get("id").asLong();
            System.out.println("반환된 id: " + id);
        } catch (Exception e) {
            // 추가적인 예외 처리 및 로깅
            e.printStackTrace();
            throw new RuntimeException("Failed to disconnect Kakao", e);
        }
    }
}