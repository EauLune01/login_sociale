package oauth2jwt.ranger.repository.user;

import oauth2jwt.ranger.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // 최초 소셜 로그인 시 사용 (회원가입 여부 확인)
    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    // 토큰 재발급 시 사용
    Optional<User> findByRefreshToken(String refreshToken);

    // 재가입 확인용 (탈퇴한 유저 포함 조회)
    // @Where 조건을 무시하고 DB에서 직접 조회하기 위해 nativeQuery 사용
    @Query(value = "SELECT * FROM users WHERE provider = :provider AND provider_id = :providerId", nativeQuery = true)
    Optional<User> findByProviderAndProviderIdIncludingDeleted(@Param("provider") String provider, @Param("providerId") String providerId);

}
