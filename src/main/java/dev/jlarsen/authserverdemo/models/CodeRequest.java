package dev.jlarsen.authserverdemo.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;

@Data
public class CodeRequest implements Serializable {

    @JsonProperty("response_type")
    private String responseType;
    @JsonProperty("client_id")
    private String clientId;
    private ArrayList<String> scope;
    private String state;
    @JsonProperty("redirect_uri")
    private String redirectUri;

    public CodeRequest(String responseType, String clientId, String scope, String state, String redirectUri) {
        this.responseType = responseType;
        this.clientId = clientId;
        if (scope != null) {
            this.scope = new ArrayList<>(Arrays.asList(scope.split(" ")));
        } else {
            this.scope = new ArrayList<>();
        }
        this.state = state;
        this.redirectUri = redirectUri;
    }

}
