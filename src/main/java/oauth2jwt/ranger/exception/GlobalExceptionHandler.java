package oauth2jwt.ranger.exception;

import oauth2jwt.ranger.exception.auth.UnauthorizedException;
import org.springframework.http.HttpStatus;
import oauth2jwt.ranger.dto.global.response.ApiResponse;
import oauth2jwt.ranger.exception.auth.InvalidTokenException;
import oauth2jwt.ranger.exception.auth.TokenNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // 유효성 검증 실패 (DTO Validation)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<ApiResponse<?>> handleValidationExceptions(MethodArgumentNotValidException e) {
        // 모든 필드 에러 메시지를 문자열로 합치기
        String errorMessage = e.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                .collect(Collectors.joining(", ")); // 쉼표로 구분

        return buildErrorResponse(HttpStatus.BAD_REQUEST, errorMessage);
    }

    //UnauthorizedException
    @ExceptionHandler(UnauthorizedException.class)
    protected ResponseEntity<ApiResponse<?>> handleUnauthorizedException(UnauthorizedException e){
        return buildErrorResponse(HttpStatus.UNAUTHORIZED,e.getMessage());
    }

    //InvalidTokenException
    @ExceptionHandler(InvalidTokenException.class)
    protected ResponseEntity<ApiResponse<?>> handleInvalidTokenException(InvalidTokenException e) {
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, e.getMessage());
    }

    //TokenNotFoundException
    @ExceptionHandler(TokenNotFoundException.class)
    protected ResponseEntity<ApiResponse<?>> handleTokenNotFoundException(TokenNotFoundException e) {
        return buildErrorResponse(HttpStatus.NOT_FOUND, e.getMessage());
    }

    // 기타 모든 예외 처리 (500 Internal Server Error)
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ApiResponse<?>> handleException(Exception e) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다: " + e.getMessage());
    }

    private ResponseEntity<ApiResponse<?>> buildErrorResponse(HttpStatus status, String message) {
        ApiResponse<?> response = new ApiResponse<>(false, status.value(), message);
        return ResponseEntity.status(status).body(response);
    }

    private <T> ResponseEntity<ApiResponse<T>> buildErrorResponse(HttpStatus status, String message, T data) {
        ApiResponse<T> response = new ApiResponse<>(false, status.value(), message, data);
        return ResponseEntity.status(status).body(response);
    }
}
