package dev.jlarsen.authserverdemo.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.jlarsen.authserverdemo.exceptions.TokenException;
import dev.jlarsen.authserverdemo.exceptions.TokenRequestError;
import dev.jlarsen.authserverdemo.models.AuthClient;
import dev.jlarsen.authserverdemo.models.TokenRequest;
import dev.jlarsen.authserverdemo.models.UserEntity;
import dev.jlarsen.authserverdemo.models.UserPrincipal;
import dev.jlarsen.authserverdemo.repositories.AuthClientRepository;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class TokenService {

    @Autowired
    KeyService keyService;

    @Autowired
    AuthService authService;

    @Autowired
    CacheManager cacheManager;

    @Autowired
    AuthClientRepository authClientRepository;

    /**
     * Verifies client token requests, returns error to client if verification fails
     *
     * @param authentication authenticated client requesting token
     * @param tokenRequest   to be verified
     */
    @SneakyThrows
    public void verifyClientTokenRequest(Authentication authentication, TokenRequest tokenRequest) {
        JWSObject jwsObject = parseCode(tokenRequest.getCode());
        Map<String, Object> payload = jwsObject.getPayload().toJSONObject();

        // make sure redirect_uri still matches
        if (!payload.get("redirect_uri").equals(tokenRequest.getRedirectUri())) {
            throw new TokenException(TokenRequestError.INVALID_REQUEST);
        }

        // pull cached codes
        Cache codes = cacheManager.getCache("codes");
        if (codes == null) {
            throw new TokenException(TokenRequestError.INVALID_GRANT);
        } else {
            // make sure current client requesting token is same who requested code
            if (codes.get(authentication.getName()) == null) {
                throw new TokenException(TokenRequestError.INVALID_GRANT);
            } else {
                // make sure code is not expired
                Instant expired = Instant.parse((CharSequence) payload.get("expires"));
                if (expired.isBefore(Instant.now())) {
                    throw new TokenException(TokenRequestError.INVALID_GRANT);
                }
            }
        }

        // we currently only support the authorization_code grant type
        if (!tokenRequest.getGrantType().equals("authorization_code")) {
            throw new TokenException(TokenRequestError.UNSUPPORTED_GRANT_TYPE);
        }

        // now verify auth code signature against the keys in our JWKSet
        verifySignature(jwsObject);

        //everything looks good, remove used code from cache
        codes.evict(authentication.getName());
    }

    /**
     * Pulls an authenticated client from the database and compares it's refresh token
     * @param refreshToken sent by client
     * @param principal client requesting new access token
     */
    public void verifyRefreshToken(String refreshToken, Principal principal) {
        AuthClient client = authService.getClient(principal.getName());
        if (client == null) {
            // couldn't find client?  we just authenticated them!
            throw new TokenException(TokenRequestError.INVALID_CLIENT);
        }
        // got the client, but refresh token does not match
        if (!client.getRefreshToken().equals(refreshToken)) {
            throw new TokenException(TokenRequestError.INVALID_GRANT);
        }
    }

    /**
     * Verifies the signature of a JWS against keys in the servers JWKSet
     * @param jwsObject to be verified
     */
    public void verifySignature(JWSObject jwsObject) {
        boolean result = keyService.getJwkSet().getKeys().stream().anyMatch(jwk -> {
            try {
                return jwsObject.verify(new ECDSAVerifier((ECKey) jwk));
            } catch (JOSEException e) {
                e.printStackTrace();
            }
            return false;
        });
        if (!result) {
            // the code signature couldn't be verified against any of the keys in our JWKSet
            throw new TokenException(TokenRequestError.INVALID_GRANT);
        }
    }

    /**
     * Parses and verifies (Bearer) access tokens
     *
     * @param token to be verified
     * @return UserPrincipal to be authenticated as User who issued token
     */
    @SneakyThrows
    public UserPrincipal parseToken(String token) {

        JWSObject jwsObject = parseCode(token);

        // first verify the token signature
        verifySignature(jwsObject);

        // signature matches, get payload for exp and sub claims
        Map<String, Object> payload = jwsObject.getPayload().toJSONObject();

        // if token has expired throw exception
        Instant expired = Instant.ofEpochSecond((Long) payload.get("exp"));
        if (expired.isBefore(Instant.now())) {
            throw new TokenException(TokenRequestError.INVALID_GRANT);
        }

        String userEmail = payload.get("sub").toString();
        return new UserPrincipal(userEmail);
    }

    /**
     * Creates map to be sent as JSON object response to requesting client including access and refresh tokens
     *
     * @param authentication client token will be issued to
     * @return response
     */
    public Map<String, Object> createTokenResponse(Authentication authentication) {
        String clientId = authentication.getName();
        AuthClient authClient = authService.getClient(clientId);
        UserEntity user = authClient.getUser();

        String refreshToken = UUID.randomUUID().toString();
        Map<String, Object> map = new HashMap<>();
        map.put("access_token", createNewAccessToken(clientId, user.getEmail()));
        map.put("token_type", "bearer");
        map.put("expires_in", "21600");
        map.put("refresh_token", refreshToken);
        applyRefreshTokenToClient(clientId, refreshToken);
        return map;
    }

    /**
     * Compiles the required claims then stores them as payload in our self-signed access token
     *
     * @param clientId of client token will be issued to
     * @param email    username of User the client belongs to
     * @return access token (as a serialized self-signed JWT)
     */
    public String createNewAccessToken(String clientId, String email) {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(email)
                .issuer("http://auth-server:8081/oauth2")
                .expirationTime(Date.from(Instant.now().plus(6, ChronoUnit.HOURS)))
                .audience("http://localhost:8080")
                .issueTime(Date.from(Instant.now()))
                .claim("cid", clientId)
                .claim("accountNo", 5000)
                .build();

        // sign the token with our current signing keypair
        SignedJWT signedJWT = keyService.signJwt(claimsSet);
        return signedJWT.serialize();
    }

    /**
     * Parses a serialized code into an object for verification and payload retrieval
     *
     * @param code to be parsed
     * @return JWSObject created from parsing our self-signed code
     */
    public JWSObject parseCode(String code) {
        JWSObject jwsObject;
        try {
            // decode our self-signed auth code
            jwsObject = JWSObject.parse(code);
        } catch (java.text.ParseException e) {
            throw new TokenException(TokenRequestError.SERVER_ERROR);
        }
        return jwsObject;
    }

    /**
     * Attaches refreshToken to AuthClient
     *
     * @param clientId     of AuthClient
     * @param refreshToken to be attached
     */
    public void applyRefreshTokenToClient(String clientId, String refreshToken) {
        Optional<AuthClient> optionalClient = authClientRepository.findById(clientId);
        if (optionalClient.isPresent()) {
            AuthClient client = optionalClient.get();
            client.setRefreshToken(refreshToken);
            authClientRepository.save(client);
        }
    }
}
