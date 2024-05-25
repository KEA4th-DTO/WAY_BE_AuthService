package com.dto.way.auth.global.config;

import com.dto.way.auth.global.JwtTokenProvider;
import com.dto.way.auth.global.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/auth-service/v3/api-docs/**", "/auth-service/swagger-ui/**", "/auth-service/swagger-resources/**").permitAll()
                        .requestMatchers("/auth-service/login").permitAll()
                        .requestMatchers("/auth-service/signup").permitAll()
                        .requestMatchers("/auth-service/logout").permitAll()
                        .requestMatchers("/auth-service/recreate-token").permitAll()
                        .requestMatchers("/auth-service/check-email").permitAll()
                        .requestMatchers("/auth-service/check-nickname").permitAll()
                        .requestMatchers("/auth-service/send-mail-certification").permitAll()
                        .requestMatchers("/auth-service/verify").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // React에서 비밀번호를 암호화하여 보내기 때문에 불필요
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
