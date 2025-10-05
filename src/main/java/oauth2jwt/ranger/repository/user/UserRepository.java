package oauth2jwt.ranger.repository.user;

import oauth2jwt.ranger.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 최초 소셜 로그인 시 사용 (회원가입 여부 확인)
    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    // JWT 토큰 검증 및 로그아웃 시 사용
    Optional<User> findByName(String name);

    // 토큰 재발급 시 사용
    Optional<User> findByRefreshToken(String refreshToken);
}
