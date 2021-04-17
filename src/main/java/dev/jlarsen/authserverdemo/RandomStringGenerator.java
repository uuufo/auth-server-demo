package dev.jlarsen.authserverdemo;

import java.security.SecureRandom;
import java.util.Base64;

public class RandomStringGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();

    public String generate() {

        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }
}
