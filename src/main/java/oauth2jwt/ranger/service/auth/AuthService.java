package oauth2jwt.ranger.service.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauth2jwt.ranger.auth.jwt.JwtTokenProvider;
import oauth2jwt.ranger.dto.auth.response.TokenResponse;
import oauth2jwt.ranger.exception.auth.InvalidTokenException;
import oauth2jwt.ranger.exception.auth.TokenNotFoundException;
import oauth2jwt.ranger.domain.user.User;
import oauth2jwt.ranger.exception.auth.UnauthorizedException;
import oauth2jwt.ranger.repository.user.UserRepository;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;
    private final SocialUnlinkService socialUnlinkService;

    //토큰 재발급
    public TokenResponse reissueTokens(String accessToken, String refreshToken) {

        // 예외 처리
        if (accessToken != null && isBlacklisted(accessToken)) {
            throw new UnauthorizedException("로그아웃된 사용자입니다.");
        }

        // 1. Refresh Token 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("유효하지 않은 Refresh Token 입니다.");
        }

        // 2. DB에서 유저 조회
        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new TokenNotFoundException("저장소에 Refresh Token이 존재하지 않습니다."));

        // 3. 새 토큰 생성
        String newAccessToken = jwtTokenProvider.createAccessToken(jwtTokenProvider.getAuthenticationFromUser(user));
        String newRefreshToken = jwtTokenProvider.createRefreshToken();

        // 4. DB 업데이트 (Rotation)
        user.updateRefreshToken(newRefreshToken);

        return TokenResponse.of(newAccessToken, newRefreshToken);
    }

    public void logout(User user, String accessToken) {
        if (user == null) {
            throw new UnauthorizedException("로그인이 필요합니다.");
        }

        // 1. DB에서 Refresh Token 삭제
        user.updateRefreshToken(null);

        // 2. Access Token 블랙리스트 등록
        // ✅ 복잡한 시간 계산/저장 로직을 헬퍼 메서드로 위임
        if (accessToken != null) {
            registerBlacklist(accessToken, "logout");
        }

        log.info("로그아웃 완료: {}", user.getUsername());
    }

    public void withdraw(User principal, String accessToken) {
        if (principal == null) {
            throw new UnauthorizedException("로그인이 필요합니다.");
        }

        // ✅ [핵심 수정] 컨트롤러에서 받은 User는 JWT에서 만든 '껍데기'입니다.
        // provider, access_token 등의 정보를 얻기 위해 DB에서 '진짜 유저'를 다시 조회합니다.
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new TokenNotFoundException("사용자 정보를 찾을 수 없습니다."));

        log.info("회원 탈퇴 프로세스 시작: username={}, provider={}", user.getUsername(), user.getProvider());

        // 1. 소셜 플랫폼 연동 해제 (이제 user.getProvider()가 null이 아닙니다!)
        socialUnlinkService.unlink(
                user.getProvider(),
                user.getProviderId(),
                user.getProviderAccessToken(),
                user.getProviderRefreshToken()
        );

        // 2. DB 삭제 (Soft Delete)
        userRepository.delete(user);

        // 3. 블랙리스트 등록
        if (accessToken != null) {
            registerBlacklist(accessToken, "withdraw");
        }

        log.info("회원 탈퇴 처리 완료 (DB Soft Delete + Social Unlink + Blacklist)");
    }

    // 블랙리스트 등록 공통 로직
    private void registerBlacklist(String accessToken, String value) {
        long remainingMillis = jwtTokenProvider.getRemainingTime(accessToken);
        if (remainingMillis > 0) {
            redisTemplate.opsForValue().set(
                    "blacklist:" + accessToken,
                    value,
                    remainingMillis,
                    TimeUnit.MILLISECONDS
            );
            log.info("Access Token 블랙리스트 등록: {} (만료까지 {}ms)", value, remainingMillis);
        }
    }

    // 블랙리스트 확인 로직
    private boolean isBlacklisted(String accessToken) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + accessToken));
    }
}
