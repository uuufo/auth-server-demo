package dev.jlarsen.authserverdemo.exceptions;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum CodeRequestError {

    INVALID_REQUEST("invalid_request",
            "missing parameter, invalid parameter, or is otherwise invalid request"),
    ACCESS_DENIED("access_denied",
            "the user or authorization server denied the request"),
    UNAUTHORIZED_CLIENT("unauthorized_client",
            "the client is not allowed to request an authorization code using this method"),
    //the client is not allowed to request an authorization code using this method,
    // for example if a confidential client attempts to use the implicit grant type.

    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type",
            "the server does not support obtaining an authorization code using this method"),
    INVALID_SCOPE("invalid_scope",
            "the requested scope is invalid or unknown"),
    SERVER_ERROR("server_error",
     "the server reported a 500 Internal Server Error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable",
     "if the server is undergoing maintenance, or is otherwise unavailable"),
    NONE("none", "everything looks good, proceed");

    private final String error;
    @JsonProperty("error_description")
    private final String errorDescription;

    CodeRequestError(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
