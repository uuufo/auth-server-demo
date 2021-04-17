package dev.jlarsen.authserverdemo.exceptions;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum TokenRequestError {

    INVALID_REQUEST("invalid_request",
            "missing, invalid, or unsupported parameter, or otherwise invalid request"),
    // The request is missing a parameter so the server can’t proceed with the request.
    // This may also be returned if the request includes an unsupported parameter or repeats a parameter.

    INVALID_CLIENT("invalid_client", "client authentication failed"),
    // Client authentication failed, such as if the request contains an invalid client ID or secret.
    // Send an HTTP 401 response in this case.

    INVALID_GRANT("invalid_grant",
            "the authorization code is invalid or expired or redirect_uri mismatch"),
    // The authorization code (or user’s password for the password grant type) is invalid or expired.
    // This is also the error you would return if the redirect URL given in the authorization grant does
    // not match the URL provided in this access token request.

    INVALID_SCOPE("invalid_scope", "the requested scope was invalid or unsupported"),
    // For access token requests that include a scope, this error indicates an invalid scope value in the request.

    UNAUTHORIZED_CLIENT("unauthorized_client",
            "this client is not authorized to use the requested grant type"),
    // This client is not authorized to use the requested grant type.  For example, if you restrict which
    // applications can use the Implicit grant, you would return this error for the other apps.

    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type",
            "the requested grant type is unknown or invalid"),
    // If a grant type is requested that the authorization server doesn’t recognize, use this code.
    // Note that unknown grant types also use this specific error code rather than using the invalid_request above.

    SERVER_ERROR("server_error",
            "the server reported a 500 Internal Server Error"),

    NONE("none", "everything looks good, proceed");

    private final String error;
    @JsonProperty("error_description")
    private final String errorDescription;

    TokenRequestError(String error, String errorDescription) {
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
