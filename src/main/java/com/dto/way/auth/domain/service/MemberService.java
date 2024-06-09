package com.dto.way.auth.domain.service;

import com.dto.way.auth.domain.entity.*;
import com.dto.way.auth.domain.repository.MemberRepository;
import com.dto.way.auth.domain.repository.TagRepository;
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
import static com.dto.way.auth.web.converter.MemberConverter.createMemberRequestDTOToMember;
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
    private final TagRepository tagRepository;
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

        Member member = createMemberRequestDTOToMember(createMemberRequestDTO, password);

        memberRepository.saveAndFlush(member);

        return MEMBER_SIGNUP.getCode();
    }

    @Transactional
    public void initTag(Member member) {
        Tag tag = Tag.builder()
                .taggedMember(member)
                .wayTag1("태그1")
                .wayTag2("태그2")
                .wayTag3("태그3")
                .build();

        Tag savedTag = tagRepository.saveAndFlush(tag);

        // Log the saved tag to ensure taggedMember is not null
        System.out.println("Saved Tag ID: " + savedTag.getId());
        System.out.println("Tagged Member in Tag: " + savedTag.getTaggedMember().getId());

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

        /**
         * 문제 발생
         * 1. 카카오 정보에 이름이 없어서 이름을 모름
         * 2. 카카오로 로그인하면 비밀번호가 암호화되지 않고 들어감
         */
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
