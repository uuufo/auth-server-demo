package dev.jlarsen.authserverdemo.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Throw and render a view with error locally, since there is an issue with the redirect_uri
 */
@ResponseStatus(value= HttpStatus.BAD_REQUEST)
public class RedirectUriException extends RuntimeException {

    public RedirectUriException() {
        super("invalid_request - invalid parameter, or otherwise invalid request");
    }
}
