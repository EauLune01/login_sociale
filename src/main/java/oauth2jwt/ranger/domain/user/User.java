package oauth2jwt.ranger.domain.user;

import jakarta.persistence.*;
import lombok.*;
import oauth2jwt.ranger.domain.role.Role;
import oauth2jwt.ranger.domain.status.UserStatus;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(
        name = "users",
        uniqueConstraints = {
                // provider와 providerId의 조합은 유니크해야 함 (동일 계정 중복 가입 방지)
                @UniqueConstraint(columnNames = {"provider", "providerId"})
        }
)
// repository.delete(user) 호출 시 실제 DELETE 쿼리 대신 실행될 SQL
@SQLDelete(sql = "UPDATE users SET status = 'DELETED', deleted_at = CURRENT_TIMESTAMP, refresh_token = NULL, provider_access_token = NULL, provider_refresh_token = NULL WHERE id = ?")
// 조회(SELECT) 시 자동으로 적용될 조건 (삭제된 유저는 조회되지 않음)
@Where(clause = "status = 'ACTIVE'")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username; // 시스템 내부 식별자 (ex: "google_10293...")

    @Column(nullable = false)
    private String name; // 사용자 이름 (닉네임)

    private String email; // 이메일

    private String profile; // 프로필 이미지 URL

    // OAuth2 제공자 정보 (google, kakao, naver, facebook)
    @Column(nullable = false)
    private String provider;

    @Column(nullable = false)
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role; // ROLE_USER, ROLE_ADMIN

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    // 탈퇴 일시
    private LocalDateTime deletedAt;

    // =================================================================
    // 🪙 토큰 관리 필드
    // =================================================================

    // 1. 우리 서비스(Ranger)의 JWT Refresh Token
    //    (로그아웃/탈퇴 시 NULL 처리를 위해 변경 가능해야 함)
    private String refreshToken;

    // 2. 소셜 플랫폼(Google, Naver 등)의 Access Token
    //    (회원 탈퇴 시 연동 해제 API 호출용)
    @Column(length = 1024)
    private String providerAccessToken;

    // 3. 소셜 플랫폼의 Refresh Token (범용)
    //    (Access Token 만료 시 갱신하여 연동 해제하기 위함)
    @Column(length = 1024)
    private String providerRefreshToken;


    // =================================================================
    // 🔧 비즈니스 편의 메서드 (Setter 대신 사용)
    // =================================================================

    //이름 업데이트
    public void updateName(String newName) {
        this.name = newName;
    }


    // 우리 서비스 JWT Refresh Token 업데이트
    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // 소셜 플랫폼 토큰 업데이트 (로그인 할 때마다 최신화)
    public void updateProviderTokens(String accessToken, String refreshToken) {
        this.providerAccessToken = accessToken;
        // Refresh Token은 발급될 때만 업데이트 (매번 발급 안 될 수도 있음)
        if (refreshToken != null) {
            this.providerRefreshToken = refreshToken;
        }
    }

    // 탈퇴한 유저 재활성화 (재가입 시 사용)
    public void reActivate() {
        this.status = UserStatus.ACTIVE;
        this.deletedAt = null;
    }

    // =================================================================
    // 🔐 UserDetails 인터페이스 구현
    // =================================================================
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override public String getPassword() { return null; } // 소셜 로그인이므로 비밀번호 없음
    @Override public String getUsername() { return this.username; }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() {
        // ACTIVE 상태인 경우에만 계정 활성화
        return this.status == UserStatus.ACTIVE;
    }
}

