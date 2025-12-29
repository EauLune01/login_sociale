package oauth2jwt.ranger.controller.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import oauth2jwt.ranger.auth.CustomOAuth2User;
import oauth2jwt.ranger.auth.jwt.JwtConstants;
import oauth2jwt.ranger.domain.user.User;
import oauth2jwt.ranger.dto.auth.request.RefreshTokenRequest;
import oauth2jwt.ranger.dto.auth.response.TokenResponse;
import oauth2jwt.ranger.dto.global.response.ApiResponse;
import oauth2jwt.ranger.service.auth.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;

@Slf4j
@Tag(name = "인증 (Auth)", description = "토큰 재발급, 로그아웃 등 사용자 인증 관련 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @Operation(
            summary = "Access Token 재발급",
            description = "만료된 Access Token과 Refresh Token을 함께 보내 새로운 토큰들을 발급받습니다.",
            security = {}
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "토큰 재발급 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "블랙리스트 또는 유효하지 않은 Refresh Token",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "DB에 Refresh Token 없음",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refreshToken(
            @RequestHeader(value = JwtConstants.HEADER_STRING, required = false) String authHeader,
            @Valid @RequestBody RefreshTokenRequest request) {

        String accessToken = extractAccessToken(authHeader);

        TokenResponse tokenResponse = authService.reissueTokens(accessToken, request.getRefreshToken());

        return ResponseEntity.ok(
                new ApiResponse<>(true, 200, "토큰이 성공적으로 재발급되었습니다.", tokenResponse)
        );
    }

    // =================================================================
    // 🚪 로그아웃
    // =================================================================
    @Operation(
            summary = "로그아웃",
            description = "현재 로그인된 사용자를 로그아웃 처리하고 Refresh Token을 무효화합니다.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "로그아웃 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal CustomOAuth2User customOAuth2User,
            @RequestHeader(value = JwtConstants.HEADER_STRING, required = false) String authHeader
    ) {

        User loginUser = (customOAuth2User != null) ? customOAuth2User.getUser() : null;
        String accessToken = extractAccessToken(authHeader);

        authService.logout(loginUser, accessToken);

        return ResponseEntity.ok(
                new ApiResponse<>(true, HttpStatus.OK.value(), "성공적으로 로그아웃되었습니다.")
        );
    }

    // =================================================================
    // 💀 회원 탈퇴
    // =================================================================
    @Operation(
            summary = "회원 탈퇴",
            description = "계정을 삭제하고, 소셜 연동을 끊으며, 현재 토큰을 차단(로그아웃)합니다.",
            security = { @SecurityRequirement(name = "bearerAuth") }
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "204", description = "회원 탈퇴 성공") // ✅ 204로 변경
    })
    @DeleteMapping("/withdraw")
    public ResponseEntity<ApiResponse<Void>> withdraw(
            @AuthenticationPrincipal CustomOAuth2User customOAuth2User,
            @RequestHeader(value = JwtConstants.HEADER_STRING, required = false) String authHeader
    ) {
        User loginUser = (customOAuth2User != null) ? customOAuth2User.getUser() : null;

        String accessToken = extractAccessToken(authHeader);

        authService.withdraw(loginUser, accessToken);

        // 204 No Content 반환
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .body(new ApiResponse<>(true, HttpStatus.NO_CONTENT.value(), "성공적으로 회원 탈퇴 처리되었습니다.", null));
    }

    // =================================================================
    // 🛠️ Private Helper Methods
    // =================================================================

    // "Bearer " 접두사를 제거하고 토큰만 추출하는 공통 메서드
    private String extractAccessToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith(JwtConstants.TOKEN_PREFIX)) {
            return authHeader.substring(JwtConstants.TOKEN_PREFIX.length());
        }
        return null;
    }
}