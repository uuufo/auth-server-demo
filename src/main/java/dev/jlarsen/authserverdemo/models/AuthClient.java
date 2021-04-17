package dev.jlarsen.authserverdemo.models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.HashMap;

@Data
@Entity
public class AuthClient {

    @Id
    @JsonProperty("client_id")
    private String clientId;
    @JsonProperty("client_secret")
    private String clientSecret;
    @JsonProperty("redirect_uri")
    private String redirectUri;
    private ArrayList<String> scope;
    private HashMap<String, String> claims;
    private ArrayList<String> grants;
    @JsonIgnore
    private String name;
    // todo - find a way around this besides multiple UserDetailsServices?
    // since we are hashing user passwords with bcrypt, Spring wants clientSecret to be hashed as well
    // (because it's used for authentication)
    // that is fine, since the client has a copy of the secret also, but i want to display it to the user here
    // so we'll keep a copy in plain text for that
    @JsonIgnore
    private String plainSecret;

    @JsonBackReference
    @OneToOne(fetch = FetchType.EAGER)
//    @MapsId
    @JoinColumn(name = "user_id")
    private UserEntity user;

    private String refreshToken;

    public AuthClient(String clientId, String plainSecret, String clientSecret, String redirectUri, ArrayList<String> scope,
                      HashMap<String, String> claims, ArrayList<String> grants, String name, UserEntity user, String refreshToken) {
        this.clientId = clientId;
        this.plainSecret = plainSecret;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.claims = claims;
        this.grants = grants;
        this.name = name;
        this.user = user;
        this.refreshToken = refreshToken;
    }

    public AuthClient() {
    }
}
