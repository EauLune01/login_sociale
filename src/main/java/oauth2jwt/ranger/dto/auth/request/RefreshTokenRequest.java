package oauth2jwt.ranger.dto.auth.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "RefreshTokenRequest", description = "리프레시 토큰 재발급 요청 바디")
public class RefreshTokenRequest {

    @Schema(
            description = "Refresh Token",
            example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    @NotBlank(message = "리프레시 토큰은 필수입니다.")
    private String refreshToken;
}
