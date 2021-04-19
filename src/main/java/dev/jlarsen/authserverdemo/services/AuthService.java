package dev.jlarsen.authserverdemo.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.jlarsen.authserverdemo.exceptions.CodeRequestError;
import dev.jlarsen.authserverdemo.exceptions.TokenException;
import dev.jlarsen.authserverdemo.exceptions.TokenRequestError;
import dev.jlarsen.authserverdemo.models.AuthClient;
import dev.jlarsen.authserverdemo.models.CodeRequest;
import dev.jlarsen.authserverdemo.repositories.AuthClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CachePut;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class AuthService {

    @Autowired
    KeyService keyService;

    @Autowired
    AuthClientRepository authClientRepository;

    @Autowired
    ObjectMapper objectMapper;

    /**
     * Verifies client authorization code requests
     * @param codeRequest request to be verified
     * @return CodeRequestError.NONE if code passes verification
     */
    public CodeRequestError verifyClientCodeRequest(CodeRequest codeRequest) {
        AuthClient client;
        Optional<AuthClient> optional = authClientRepository.findById(codeRequest.getClientId());

        // first verify client_id exists and redirect_uri match
        if (optional.isPresent() && optional.get().getRedirectUri().equals(codeRequest.getRedirectUri())) {
            client = optional.get();
        } else {
            // we will show this locally and not redirect
            return CodeRequestError.INVALID_REQUEST;
        }

        // we only support the authorization code grant type currently
        if (!codeRequest.getResponseType().equals("code")) {
            return CodeRequestError.UNSUPPORTED_RESPONSE_TYPE;
        }

        // we only support the authorization code grant type currently
        if (!client.getGrants().contains(codeRequest.getResponseType())) {
            return CodeRequestError.UNAUTHORIZED_CLIENT;
        }

        // verify requested scope
        ArrayList<String> requestedScope = codeRequest.getScope();
        ArrayList<String> authorizedScope = client.getScope();
        if (requestedScope.retainAll(authorizedScope)) {
            return CodeRequestError.INVALID_SCOPE;
        }
        return CodeRequestError.NONE;
    }

    /**
     * Creates a map with required information then stores it as payload in our self-signed authorization code
     * @param codeRequest the code request
     * @param principal client requesting code
     * @return authorization code (as a serialized self-signed JWT)
     */
    @CachePut(value = "codes", key = "#codeRequest.clientId")
    public String getAuthCode(CodeRequest codeRequest, Principal principal) {
        // create map of parameters to be stored as payload inside code
        Map<String, Object> map = new HashMap<>();
        map.put("client_id", codeRequest.getClientId());
        map.put("redirect_uri", codeRequest.getRedirectUri());
        map.put("user_id", principal.getName());
        map.put("code_id", UUID.randomUUID().toString());
        map.put("expires", Instant.now().plus(3, ChronoUnit.MINUTES).toString());

        // create self-signed JWT (JWS) as auth code and serialize it for return to client
        return keyService.createJws(map).serialize();
    }

    /**
     * Used to encode authorization code request errors as URL parameters
     * @param error to be encoded
     * @return error as parameter to be added to redirect URL
     */
    public String getEncodedErrorParams(CodeRequestError error) {
        Map<String, String> params = objectMapper.convertValue(error, Map.class);
        StringBuilder sb = new StringBuilder("?");
        try {
            for (String key : params.keySet()) {
                sb.append(key).append("=").append(URLEncoder.encode(params.get(key),
                        StandardCharsets.UTF_8.name()).replace("+", "%20")).append("&");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    /**
     * Retrieves an AuthClient from the repository
     * @param clientId of AuthClient to be retrieved
     * @return AuthClient
     */
    public AuthClient getClient(String clientId) {
        Optional<AuthClient> client = authClientRepository.findById(clientId);
        return client.orElse(null);
    }
}
