package oauth2jwt.ranger.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauth2jwt.ranger.auth.CustomOAuth2User;
import oauth2jwt.ranger.domain.role.Role;
import oauth2jwt.ranger.domain.status.UserStatus;
import oauth2jwt.ranger.domain.user.User;
import oauth2jwt.ranger.oauth2.provider.*;
import oauth2jwt.ranger.repository.user.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 1. 소셜 토큰 추출 (탈퇴 시 연동 해제용 - 이건 필수라 남김)
        String providerAccessToken = userRequest.getAccessToken().getTokenValue();
        String providerRefreshToken = (String) userRequest.getAdditionalParameters().get("refresh_token");

        // 2. 정보 파싱
        OAuth2UserInfo oAuth2UserInfo;
        switch (registrationId) {
            case "google" -> oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
            case "naver" -> oAuth2UserInfo = new NaverUserInfo(oAuth2User.getAttributes());
            case "kakao" -> oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
            case "facebook" -> oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();

        // 3. DB 조회 및 처리
        User user = userRepository.findByProviderAndProviderIdIncludingDeleted(provider, providerId)
                .map(existingUser -> {
                    // ✅ 토큰 최신화
                    existingUser.updateProviderTokens(providerAccessToken, providerRefreshToken);

                    // ✅ 탈퇴한 유저라면 복구 (Re-activate)
                    if (existingUser.getStatus() == UserStatus.DELETED) {
                        existingUser.reActivate();
                        // 재가입 시 닉네임은 소셜 정보로 초기화 (프로필 사진 로직 삭제됨)
                        existingUser.updateName(oAuth2UserInfo.getName());
                    }
                    // ACTIVE 유저는 닉네임 변경 안 함 (기존 유지)

                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> saveNewUser(oAuth2UserInfo, providerAccessToken, providerRefreshToken));

        return new CustomOAuth2User(user, oAuth2UserInfo.getAttributes());
    }

    private User saveNewUser(OAuth2UserInfo oAuth2UserInfo, String accessToken, String refreshToken) {
        String username = oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId();

        User newUser = User.builder()
                .username(username)
                .name(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .provider(oAuth2UserInfo.getProvider())
                .providerId(oAuth2UserInfo.getProviderId())
                .role(Role.ROLE_USER)
                .providerAccessToken(accessToken)
                .providerRefreshToken(refreshToken)
                .status(UserStatus.ACTIVE)
                .build();

        return userRepository.save(newUser);
    }
}