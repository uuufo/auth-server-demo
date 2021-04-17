package dev.jlarsen.authserverdemo.exceptions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class TokenExceptionHandler {

    @ResponseBody
    @ExceptionHandler(value = TokenException.class)
    public ResponseEntity<?> handleException(TokenException exception) throws JsonProcessingException {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(new ObjectMapper().writeValueAsString(exception.getError()));
    }
}