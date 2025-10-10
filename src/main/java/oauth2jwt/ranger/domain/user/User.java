package oauth2jwt.ranger.domain.user;
import jakarta.persistence.*;
import lombok.*;
import oauth2jwt.ranger.domain.role.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username; // "provider_providerId" 형식의 고유 식별자

    @Column(unique = true)
    private String name; // 사용자 이름 (또는 nickname)
    @Column(unique = true)
    private String email; // 이메일
    private String provider; // OAuth2 제공자 (google, kakao, naver)
    private String providerId; // 제공자별 고유 ID

    @Enumerated(EnumType.STRING)
    private Role role; // ROLE_USER, ROLE_ADMIN 등

    // JWT Refresh Token for 재발급용 ( Access Token은 DB에 저장 필요 X)
    private String refreshToken;

    // Refresh Token 업데이트를 위한 메서드
    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // [추가] 토큰에서 stateless 유저 객체를 생성하기 위한 생성자
    public User(Long id, String name) {
        this.id = id;
        this.name = name;
        this.role = Role.ROLE_USER;
    }

    // === UserDetails 구현 ===
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override public String getPassword() { return null; } // OAuth2는 비밀번호 없음
    @Override public String getUsername() {return this.username;}
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
