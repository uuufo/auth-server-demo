package dev.jlarsen.authserverdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.jlarsen.authserverdemo.models.TokenRequest;
import dev.jlarsen.authserverdemo.services.AuthService;
import dev.jlarsen.authserverdemo.services.KeyService;
import dev.jlarsen.authserverdemo.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.*;

@RestController
public class AuthController {

    @Autowired
    KeyService keyService;

    @Autowired
    TokenService tokenService;

    @Autowired
    AuthService authService;

    @Autowired
    ObjectMapper objectMapper;


    /**
     * Token endpoint used by OAuth 2.0 client to request an access token
     * If request is verified an access token is issued, otherwise an error is returned to requesting client
     * @param params token request object containing grant_type, redirect_uri, and previously issued auth code
     * @param authentication current authenticated client (using Basic authentication)
     * @return HttpEntity containing appropriate headers and information along with access token
     */
    @PreAuthorize("hasAuthority('ROLE_CLIENT')")
    @PostMapping(value = "/token", consumes = "application/x-www-form-urlencoded")
    public HttpEntity<?> getToken(@RequestParam Map<String, String> params, Authentication authentication) {
        if (params.get("grant_type").equals("refresh_token")) {
            tokenService.verifyRefreshToken(params.get("refresh_token"), authentication);
        } else {
            TokenRequest tokenRequest = objectMapper.convertValue(params, TokenRequest.class);
            tokenService.verifyClientTokenRequest(authentication, tokenRequest);
        }

        Map<String, Object> response = tokenService.createTokenResponse(authentication);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setCacheControl(CacheControl.noStore());
        headers.setPragma("no-cache");
        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(response, headers);
        return httpEntity;
    }

    /**
     * Public endpoint used to provide configuration details to OIDC/OAuth 2.0 clients
     * @return JSON object containing provider configuration details
     */
    @GetMapping(value = "/.well-known/openid-configuration")
    public Map<String, Object> provideConfig() {
        // todo - store this data somewhere else
        Map<String, Object> map = new HashMap<>();
        map.put("issuer", "http://auth-server:8081/oauth2");
        map.put("authorization_endpoint", "http://auth-server:8081/oauth2/authorize");
        map.put("token_endpoint", "http://auth-server:8081/oauth2/token");
        map.put("jwks_uri", "http://auth-server:8081/oauth2/.well-known/jwks.json");
        map.put("userinfo_endpoint", "http://auth-server:8081/oauth2/userinfo");
        map.put("response_types_supported", new ArrayList<>(Arrays.asList("code", "token")));
        map.put("grant_types_supported", new ArrayList<>(Arrays.asList("authorization_code", "refresh_token")));
        map.put("scopes_supported", new ArrayList<>(Arrays.asList("read:transactions", "test")));
        map.put("claims_supported", new ArrayList<>(Arrays.asList("accountNo", "test")));
        map.put("subject_types_supported", new ArrayList<>(Collections.singletonList("public")));
        map.put("id_token_signing_alg_values_supported", new ArrayList<>(Arrays.asList("RS256", "ES256")));
        map.put("token_endpoint_auth_signing_alg_values_supported", new ArrayList<>(Arrays.asList("RS256", "ES256")));
        return map;
    }

    /**
     * Public endpoint used to provide this servers public key set
     * @return JSON object containing current JWKSet
     */
    @GetMapping(value = "/.well-known/jwks.json")
    public Map<String, Object> providePublicJwks() {
        return keyService.getJwkSet().toJSONObject(true);
    }

    /**
     * Endpoint provides information about User that approve client authentication
     * @param principal current authenticated client (using Bearer authentication)
     * @return JSON object containing username (email address) of User that client belongs to
     */
    @PreAuthorize("hasAuthority('ROLE_CLIENT')")
    @GetMapping(value = "/userinfo")
    public Map<String, Object> provideUserInfo(Principal principal) {
        Map<String, Object> map = new HashMap<>();
        map.put("sub", principal.getName());
        return map;
    }
}
