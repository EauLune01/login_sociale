package oauth2jwt.ranger.service.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauth2jwt.ranger.dto.auth.response.OAuth2TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Slf4j
@Service
@RequiredArgsConstructor
public class SocialUnlinkService {

    private final WebClient webClient;

    // =================================================================
    // 🔐 Client ID & Secret 주입 (application.yml)
    // =================================================================

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;
    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;
    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String kakaoClientSecret;

    // =================================================================
    // 🚀 메인 메서드: 연동 해제 (Unlink)
    // =================================================================
    public void unlink(String provider, String providerId, String accessToken, String refreshToken) {
        // 1. 토큰 갱신 시도 (Refresh Token이 있을 경우)
        String validAccessToken = accessToken;
        if (StringUtils.hasText(refreshToken)) {
            String newAccessToken = refreshAccessToken(provider, refreshToken);
            if (newAccessToken != null) {
                validAccessToken = newAccessToken;
                log.info("✅ {} Access Token 갱신 완료, 갱신된 토큰으로 연동 해제를 진행합니다.", provider);
            }
        }

        // 2. 연동 해제 요청
        try {
            switch (provider.toLowerCase()) {
                case "google" -> unlinkGoogle(validAccessToken);
                case "kakao" -> unlinkKakao(validAccessToken);
                case "naver" -> unlinkNaver(validAccessToken);
                case "facebook" -> unlinkFacebook(providerId, validAccessToken);
                default -> log.warn("지원하지 않는 Provider입니다: {}", provider);
            }
        } catch (Exception e) {
            // 소셜 연동 해제가 실패하더라도 우리 서비스 내부 회원 탈퇴는 계속 진행되어야 하므로 에러를 삼킴
            log.error("❌ 소셜 연동 해제 실패 (provider: {}): {}", provider, e.getMessage());
        }
    }

    // =================================================================
    // 🔄 공통: Access Token 갱신 로직
    // =================================================================
    private String refreshAccessToken(String provider, String refreshToken) {
        String url = "";
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        if ("google".equals(provider)) {
            url = "https://oauth2.googleapis.com/token";
            params.add("grant_type", "refresh_token");
            params.add("client_id", googleClientId);
            params.add("client_secret", googleClientSecret);
            params.add("refresh_token", refreshToken);
        } else if ("naver".equals(provider)) {
            url = "https://nid.naver.com/oauth2.0/token";
            params.add("grant_type", "refresh_token");
            params.add("client_id", naverClientId);
            params.add("client_secret", naverClientSecret);
            params.add("refresh_token", refreshToken);
        } else if ("kakao".equals(provider)) {
            url = "https://kauth.kakao.com/oauth/token";
            params.add("grant_type", "refresh_token");
            params.add("client_id", kakaoClientId);
            params.add("client_secret", kakaoClientSecret);
            params.add("refresh_token", refreshToken);
        } else {
            return null;
        }

        try {
            // ✅ 수정됨: uri(url)에 String을 바로 넣습니다. (uriBuilder 사용 X -> 에러 해결)
            OAuth2TokenResponse response = webClient.post()
                    .uri(url)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(params))
                    .retrieve()
                    .bodyToMono(OAuth2TokenResponse.class)
                    .block();

            if (response != null && StringUtils.hasText(response.getAccessToken())) {
                return response.getAccessToken();
            }
        } catch (Exception e) {
            log.warn("⚠️ {} 토큰 갱신 실패 (기존 Access Token으로 시도합니다): {}", provider, e.getMessage());
        }
        return null;
    }

    // =================================================================
    // ✂️ 각 Provider별 연동 해제 구현 (Host Not Specified 해결 버전)
    // =================================================================

    private void unlinkGoogle(String accessToken) {
        String url = "https://oauth2.googleapis.com/revoke";

        // ✅ UriComponentsBuilder 사용
        URI uri = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("token", accessToken)
                .build().toUri();

        webClient.post()
                .uri(uri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("✅ 구글 연동 해제 완료");
    }

    private void unlinkNaver(String accessToken) {
        String url = "https://nid.naver.com/oauth2.0/token";

        // ✅ UriComponentsBuilder 사용 (핵심 해결책)
        URI uri = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("grant_type", "delete")
                .queryParam("client_id", naverClientId)
                .queryParam("client_secret", naverClientSecret)
                .queryParam("access_token", accessToken)
                .queryParam("service_provider", "NAVER")
                .build().toUri();

        webClient.post()
                .uri(uri)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("✅ 네이버 연동 해제 완료");
    }

    private void unlinkKakao(String accessToken) {
        String url = "https://kapi.kakao.com/v1/user/unlink";

        // 카카오는 헤더만 쓰므로 String URL 바로 사용 가능
        webClient.post()
                .uri(url)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("✅ 카카오 연동 해제 완료");
    }

    private void unlinkFacebook(String providerId, String accessToken) {
        String url = "https://graph.facebook.com/{userId}/permissions";

        // ✅ UriComponentsBuilder 사용 (Path Variable 치환)
        URI uri = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("access_token", accessToken)
                .buildAndExpand(providerId)
                .toUri();

        webClient.delete()
                .uri(uri)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("✅ 페이스북 연동 해제 완료");
    }
}

