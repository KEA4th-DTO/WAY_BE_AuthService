package com.dto.way.auth.web.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class KakaoInfo {

    private Long id;
    private String nickname;
    private String email;

}
