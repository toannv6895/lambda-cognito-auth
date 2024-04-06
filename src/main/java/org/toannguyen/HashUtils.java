package org.toannguyen;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashUtils {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";

    public static String computeSecretHash(String clientId, String clientSecret, String username) {
        byte[] output = hmac(
                clientSecret.getBytes(StandardCharsets.UTF_8),
                username.getBytes(StandardCharsets.UTF_8),
                clientId.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(output);
    }

    public static byte[] hmac(byte[] key, byte[]... inputs) {
        SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_ALGORITHM);
        Mac mac = null;
        try {
            mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(signingKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        for (byte[] input : inputs) {
            mac.update(input);
        }
        return mac.doFinal();
    }
}