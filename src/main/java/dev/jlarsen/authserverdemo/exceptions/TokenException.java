package dev.jlarsen.authserverdemo.exceptions;

import org.springframework.http.HttpStatus;

public class TokenException extends RuntimeException {

    private final TokenRequestError error;
    private final HttpStatus httpStatus;

    public TokenException(TokenRequestError error) {
        super(error.getErrorDescription());
        this.error = error;
        if (error.name().equals("INVALID_CLIENT")) {
            httpStatus = HttpStatus.UNAUTHORIZED;
        } else {
            httpStatus = HttpStatus.BAD_REQUEST;
        }
    }

    public TokenRequestError getError() {
        return error;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
