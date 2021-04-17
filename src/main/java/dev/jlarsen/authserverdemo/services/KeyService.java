package dev.jlarsen.authserverdemo.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.jlarsen.authserverdemo.models.JwkEntity;
import dev.jlarsen.authserverdemo.repositories.JwkRepository;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class KeyService {

    @Autowired
    JwkRepository jwkRepository;

    @Autowired
    ObjectMapper objectMapper;

    private final DefaultJWKSetCache jwkSetCache;

    public KeyService() {
        this.jwkSetCache = new DefaultJWKSetCache(20160, 20160, TimeUnit.MINUTES);
    }

    /**
     * Creates a new JWK from an EC keypair, also stored as a JwkEntity
     *
     * @return JWK
     */
    @SneakyThrows
    public JWK createJwk() {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(Curve.P_256.toECParameterSpec());
        KeyPair keyPair = gen.generateKeyPair();

        JWK jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey((ECPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm("ES256"))
                .build();

        JwkEntity jwkEntity = convertJwkToJwkEntity(jwk);
        jwkEntity.setId(0);
        jwkRepository.save(jwkEntity);
        return jwk;
    }

    /**
     * Creates a JWSObject using map as payload, and signs using our current key
     *
     * @param map to be stored
     * @return signed JWSObject containing our payload
     */
    @SneakyThrows
    public JWSObject createJws(Map<String, Object> map) {

        ECKey ecJWK = (ECKey) getJwkSet().getKeys().get(0);
        JWSSigner signer = new ECDSASigner(ecJWK);
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(ecJWK.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build(),
                new Payload(map));
        jwsObject.sign(signer);
        return jwsObject;
    }

    /**
     * Creates a JWT using claimSet as payload, and signs using our current key
     *
     * @param claimsSet to be stored
     * @return signed JWT containing our payload
     */
    @SneakyThrows
    public SignedJWT signJwt(JWTClaimsSet claimsSet) {
        ECKey ecJWK = (ECKey) getJwkSet().getKeys().get(0);
        JWSSigner signer = new ECDSASigner(ecJWK);
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(ecJWK.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build(),
                claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    /**
     * If JWKSet exists in cache and is not expired, return it.
     * Otherwise, handle expired keys if required and return new JWKSet
     *
     * @return JWKSet of current keys
     */
    @SneakyThrows
    public JWKSet getJwkSet() {
        // if there is a valid JWKSet in the cache, return it
        if (jwkSetCache.get() != null && !jwkSetCache.isExpired()) {
            return jwkSetCache.get();
        }
        // if the cache is empty or expired - pull keys from database
        List<JWK> jwkList = getAllJwks();
        // check for expired jwks and rotate if necessary
        JWKSet jwkSet = rotateJwks(jwkList);
        // put new JWKSet in cache and return
        jwkSetCache.put(jwkSet);
        return jwkSet;
    }

    /**
     * Retrieves all keys from the database.
     *
     * @return List of keys
     */
    public List<JWK> getAllJwks() {
        List<JWK> jwkList = new ArrayList<>();
        Iterable<JwkEntity> entries = jwkRepository.findAll();
        entries.forEach(jwkEntity -> {
            try {
                jwkList.add(jwkEntity.toJwk());
            } catch (IllegalArgumentException e) {
                // something happened, just clear all stored keys and create a new one
                clearAllJwks();
                jwkList.clear();
                e.printStackTrace();
            }
        });
        if (jwkList.size() == 0) {
            jwkList.add(createJwk());
        }
        return jwkList;
    }

    /**
     * If cache has expired, create a new signer at index (0) and move old signer at (1)
     *
     * @param jwkList to be rotated
     * @return JWKSet containing new (or current) keypairs
     */
    @Transactional
    public JWKSet rotateJwks(List<JWK> jwkList) {
        if (jwkSetCache.isExpired()) {
            JwkEntity oldSigner = convertJwkToJwkEntity(jwkList.get(0));
            oldSigner.setId(1);
            jwkRepository.deleteAll();
            jwkList.clear();
            jwkList.add(createJwk());
            jwkList.add(oldSigner.toJwk());
            jwkRepository.save(oldSigner);
        }
        return new JWKSet(jwkList);
    }

    /**
     * Remove all keys in the database
     */
    public void clearAllJwks() {
        jwkRepository.deleteAll();
    }

    /**
     * Converts a JWK to a JwkEntity
     * @param jwk to be converted
     * @return new JwkEntity, or null if exception is thrown
     */
    public JwkEntity convertJwkToJwkEntity(JWK jwk) {
        try {
            return objectMapper.readValue(jwk.toJSONString(), JwkEntity.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
