package com.dto.way.auth.domain.service;

import com.dto.way.auth.domain.entity.LoginType;
import com.dto.way.auth.domain.entity.Member;
import com.dto.way.auth.domain.entity.MemberStatus;
import com.dto.way.auth.domain.repository.MemberRepository;
import com.dto.way.auth.global.JwtTokenProvider;
import com.dto.way.auth.web.dto.JwtToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import static com.dto.way.auth.domain.entity.MemberAuth.*;
import static com.dto.way.auth.web.dto.MemberRequestDTO.*;
import static com.dto.way.auth.web.response.code.status.ErrorStatus.*;
import static com.dto.way.auth.web.response.code.status.SuccessStatus.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisService redisService;

    public static final String DEFAULT_IMAGE = "https://way-bucket-s3.s3.ap-northeast-2.amazonaws.com/profile_image/default.jpg";

    @Transactional
    public String createMember(CreateMemberRequestDTO createMemberRequestDTO) {

        // 비밀번호 일치 검사
        if (!checkEqualPassword(createMemberRequestDTO)) {

            return MEMBER_PASSWORD_NOT_MATCHED.getCode();
        }

        // 이메일 중복 검사
        if (checkEmailDuplication(createMemberRequestDTO.getEmail())) {

            return MEMBER_EMAIL_DUPLICATED.getCode();
        }

        // 닉네임 중복 검사
        if (checkNicknameDuplication(createMemberRequestDTO.getNickname())) {

            return MEMBER_NICKNAME_DUPLICATED.getCode();
        }

        String password = passwordEncoder.encode(createMemberRequestDTO.getPassword());

        /**
         * CreateMemberRequestDTO 를 기반으로 멤버 생성
         * 프로필 기본이미지 넣어줌
         * role은 CLIENT로 설정
         * 한줄 소개는 프로필 수정에서 처리
         */
        Member member = Member.builder()
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

        memberRepository.save(member);

        return MEMBER_SIGNUP.getCode();

    }

    public JwtToken login(LoginMemberRequestDTO loginMemberRequestDTO) {
        Optional<Member> member = memberRepository.findByEmail(loginMemberRequestDTO.getEmail());
        if (member.isEmpty()) { // 이메일로 멤버 조회를 실패한 경우
            return new JwtToken(MEMBER_LOGIN_FAILED.getCode(), null, null);
        } else { // 비밀번호가 일치하지 않는 경우
            if (!member.get().getPassword().equals(loginMemberRequestDTO.getPassword())) {
                return new JwtToken(MEMBER_LOGIN_FAILED.getCode(), null, null);
            }
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginMemberRequestDTO.getEmail(), loginMemberRequestDTO.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 멤버 id, nickname을 담아 token을 생성
        Long memberId = member.get().getId();
        String nickname = member.get().getNickname();
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication, memberId, nickname);

        // 7일간 refresh token을 redis에 저장
        saveRefreshToken(jwtToken.getRefreshToken(), authentication, Duration.ofDays(7));

        return jwtToken;
    }

    // 로그아웃 할 경우 redis에서 토큰 값 삭제
    public void logout(JwtToken jwtToken) {
        redisService.deleteValues(jwtToken.getRefreshToken());
    }

    public JwtToken checkRefreshTokenIsValid(String refreshToken) {

        if (redisService.getValues(refreshToken).equals("false")) { // 리프레시 토큰이 만료되었거나 없는 겅우

            return new JwtToken("Refresh Token이 만료되었거나 없습니다.", null, null);

        } else { // redis에 있는 email로 user정보를 가져온다.
            Optional<Member> memberOrNull = memberRepository.findByEmail(redisService.getValues(refreshToken));

            if (memberOrNull.isPresent()) {

                // 토큰을 재발급 받기 위해 내부적으로는 login 로직을 실행한다.
                Member member = memberOrNull.get();
                String email = member.getEmail();
                String password = member.getPassword();

                log.info("member.getPassword() = {}", member.getPassword());
                log.info("토큰 재발급!!!!");

                // 기존에 있던 토큰은 삭제
                redisService.deleteValues(refreshToken);

                return login(new LoginMemberRequestDTO(email, password));
            }

            return new JwtToken("Refresh Token과 사용자 정보가 일치하지 않습니다.", null, null);
        }
    }



    // 비밀번호와 비밀번호 확인이 같은지 체크하는 메소드
    public boolean checkEqualPassword(CreateMemberRequestDTO createMemberRequestDTO) {
        return createMemberRequestDTO.getPassword().equals(createMemberRequestDTO.getPasswordCheck());
    }

    // 닉네임 중복 검사 메소드
    public boolean checkNicknameDuplication(String nickname) {
        return memberRepository.existsByNickname(nickname);
    }

    // 이메일 중복 검사 메소드
    public boolean checkEmailDuplication(String email) {
        return memberRepository.existsByEmail(email);
    }

    private void saveRefreshToken(String refreshToken, Authentication authentication, Duration duration) {
        log.info("save token");
        redisService.setValues(refreshToken, authentication.getName(), duration);
    }

    @Transactional(readOnly = true)
    public Member findMemberByEmail(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        return member.orElse(null);
    }

    @Transactional(readOnly = true)
    public Member findMemberByNickname(String nickname) {
        Optional<Member> member = memberRepository.findByNickname(nickname);
        return member.orElse(null);
    }

    @Transactional(readOnly = true)
    public Member findMemberByMemberId(Long memberId) {
        Optional<Member> member = memberRepository.findById(memberId);
        return member.orElse(null);
    }
}
