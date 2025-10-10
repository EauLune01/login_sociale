package oauth2jwt.ranger.auth.service;

import lombok.RequiredArgsConstructor;
import oauth2jwt.ranger.auth.CustomOAuth2User;
import oauth2jwt.ranger.domain.role.Role;
import oauth2jwt.ranger.domain.user.User;
import oauth2jwt.ranger.oauth2.provider.*;
import oauth2jwt.ranger.repository.user.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 기본 OAuth2User 정보 로드
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 1️⃣ Provider별 유저 정보 파싱
        OAuth2UserInfo oAuth2UserInfo;
        switch (registrationId) {
            case "google" -> oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
            case "naver" -> oAuth2UserInfo = new NaverUserInfo(oAuth2User.getAttributes());
            case "kakao" -> oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
            case "facebook" -> oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }

        // 2️⃣ provider & providerId로 DB 조회
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();

        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseGet(() -> saveNewUser(oAuth2UserInfo));

        // 3️⃣ 즉시 flush (토큰/정보 갱신 반영 보장)
        userRepository.flush();

        // 4️⃣ CustomOAuth2User로 반환
        return new CustomOAuth2User(user, oAuth2UserInfo.getAttributes());
    }

    // 신규 유저 저장
    private User saveNewUser(OAuth2UserInfo oAuth2UserInfo) {
        String username = oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId();
        User newUser = User.builder()
                .username(username)
                .name(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .provider(oAuth2UserInfo.getProvider())
                .providerId(oAuth2UserInfo.getProviderId())
                .role(Role.ROLE_USER)
                .build();
        return userRepository.save(newUser);
    }
}

