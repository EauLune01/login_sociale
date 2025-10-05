package oauth2jwt.ranger.oauth2.provider;

import java.util.Map;

/**
 * OAuth2 제공자별로 제공하는 사용자 정보의 형식이 다르므로
 * 공통된 형식으로 변환하기 위한 인터페이스
 * 이후에 Line, Wechat, Whatsapp 등 구현체 추가 가능
 * */
public interface OAuth2UserInfo {

    // 각 제공자의 고유 사용자 ID
    String getProviderId();

    // 제공자 이름 (google, naver, kakao 등)
    String getProvider();

    // 사용자 이메일 주소
    String getEmail();

    // 사용자 이름 또는 닉네임
    String getName();

    // 사용자 정보가 담긴 원본 Map 데이터 반환
    Map<String, Object> getAttributes();
}