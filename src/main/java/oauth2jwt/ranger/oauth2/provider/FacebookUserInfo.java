package oauth2jwt.ranger.oauth2.provider;

import java.util.Map;

public class FacebookUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes; // OAuth2User.getAttributes() 결과

    public FacebookUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "facebook";
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
