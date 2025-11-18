package oauth2jwt.ranger.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauth2jwt.ranger.auth.CustomOAuth2User;
import oauth2jwt.ranger.auth.jwt.JwtTokenProvider;
import oauth2jwt.ranger.domain.user.User;

import oauth2jwt.ranger.repository.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // application.yml에서 리다이렉트 주소를 가져옵니다.
    // 기본값은 로컬 테스트용 html 경로로 설정해두었습니다.
    @Value("${app.oauth2.redirect-uri:/auth/callback.html}")
    private String redirectUri;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        // 1. 인증 객체에서 User 정보 추출
        // CustomOAuth2UserService에서 넘겨준 CustomOAuth2User 객체입니다.
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        User user = oAuth2User.getUser();

        // 2. JWT 토큰 생성 (Access & Refresh)
        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        String refreshToken = jwtTokenProvider.createRefreshToken();

        log.info("✅ 소셜 로그인 성공: {}", user.getUsername());
        log.info("🆕 JWT 토큰 발급 완료");

        // 3. Refresh Token DB 저장 (Ranger 서비스 전용 토큰)
        // 참고: 소셜 플랫폼의 토큰(providerAccessToken)은 이미 UserService에서 저장했습니다.
        // 여기서는 우리 서비스의 재발급용 토큰을 저장합니다.
        user.updateRefreshToken(refreshToken);
        userRepository.save(user); // 변경 감지(Dirty Checking)가 일어나지만, 명시적으로 save 호출

        // 4. 리다이렉트 URL 생성
        // 설정파일(application.yml)에서 불러온 주소를 사용합니다.
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build().toUriString();

        // 5. 리다이렉트 수행
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
