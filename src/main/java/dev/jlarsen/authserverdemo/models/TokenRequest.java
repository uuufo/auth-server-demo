package dev.jlarsen.authserverdemo.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenRequest {

    @JsonProperty("grant_type")
    private String grantType;
    @JsonProperty("redirect_uri")
    private String redirectUri;
    private String code;
}
