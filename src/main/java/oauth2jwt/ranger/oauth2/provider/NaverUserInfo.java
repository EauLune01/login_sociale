package oauth2jwt.ranger.oauth2.provider;

import java.util.Map;

// 네이버: 생성자에서 response 맵 추출 처리 필요
public class NaverUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    @SuppressWarnings("unchecked")
    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = (Map<String, Object>) attributes.get("response");
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
}
