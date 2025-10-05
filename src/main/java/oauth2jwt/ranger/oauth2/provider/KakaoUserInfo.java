package oauth2jwt.ranger.oauth2.provider;

import java.util.Map;

// Kakao는 사용자 정보가 properties와 kakao_account 두 개의 중첩된 객체에 나뉘어 있음
// 따라서, 닉네임(nickname)과 이메일(email)을 각각 다른 경로에서 꺼내야 힘
// 그리고 email은 따로 신청해야 받아올 수 있음(현재 코드만 구현된 상태)
public class KakaoUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    public KakaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        // Kakao의 고유 ID
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        if (account != null) {
            return (String) account.get("email"); // account_email
        }
        return null;
    }

    @Override
    public String getName() {
        // profile_nickname 사용
        Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
        if (properties != null) {
            return (String) properties.get("nickname");
        }
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
}