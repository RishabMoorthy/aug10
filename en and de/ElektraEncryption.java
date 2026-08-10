package com.sv;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ElektraEncryption {

    public static final String ENCODING_UTF8 = "UTF-8";
    public static final String AES_KEY = "AES";
    public static final String ALGO_HMAC = "HmacSHA256";
    public static final int IV_SIZE = 16;
    private static final String PUBLIC_KEY_STRING =
            "PUT_ACTUAL_PUBLIC_KEY_HERE";

    private static final String PRIVATE_KEY_STRING =
            "PUT_ACTUAL_PRIVATE_KEY_HERE";
    private static final String KEY_PUBLICO =
            "Do3VJxoVc9QBzMpk6/Vhh7xH0pqd+784Sva9BjNR6YY=";

    private static final String HASH_PUBLICO =
            "m0sfw6fhuU8vhvJoxZ0r6ZWFZmp26kRh97eihPJntfI=";

    public static PublicKey getPublicKey() throws Exception {
        return getPublicKeyFromString(PUBLIC_KEY_STRING);
    }

    public static PrivateKey getPrivateKey() throws Exception {
        return getPrivateKeyFromString(PRIVATE_KEY_STRING);
    }

    public static PublicKey getPublicKeyFromString(String publicKeyStr)
            throws Exception {

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey getPrivateKeyFromString(String privateKeyStr)
            throws Exception {

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    public static String encrypt(String message, PublicKey publicKey)
            throws Exception {

        Cipher cipher =
                Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        byte[] encryptedBytes =
                cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String encrypt(String message) throws Exception {
        return encrypt(message, getPublicKey());
    }

    public static String decrypt(
            String encryptedMessageBase64,
            PrivateKey privateKey) throws Exception {

        Cipher cipher =
                Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

        byte[] encryptedBytes =
                Base64.getDecoder().decode(encryptedMessageBase64);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static String decrypt(String encryptedMessageBase64)
            throws Exception {
        return decrypt(encryptedMessageBase64, getPrivateKey());
    }

    public static String encryptAESHMac(
            String plainText,
            String keyPublico,
            String hashPulico) {

        try {
            SecretKeySpec aesKey = new SecretKeySpec(Base64.getDecoder().decode(keyPublico), AES_KEY);

            SecretKeySpec hmacKey = new SecretKeySpec(Base64.getDecoder().decode(hashPulico), ALGO_HMAC);

            byte[] iv = generateInitializationVector();

            Cipher cipher =
                    Cipher.getInstance("AES/CBC/PKCS5PADDING");

            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    aesKey,
                    new IvParameterSpec(iv)
            );

            byte[] cipherText =
                    cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] ivCipherText = concatenateBytes(iv, cipherText);

            byte[] hmac = generateHmac(hmacKey, ivCipherText);

            byte[] finalBytes = concatenateBytes(ivCipherText, hmac);

            return Base64.getEncoder().encodeToString(finalBytes);

        } catch (Exception exp) {
            exp.printStackTrace();
            return "ERRORMESSAGE:ElektraEncryptionUtility-encryptAESHMac:Failed to encrypt";
        }
    }

    public static String decryptAESHMac(
            String encryptedText,
            String keyPublico,
            String hashPulico) {

        try {
            SecretKeySpec aesKey = new SecretKeySpec(
                    Base64.getDecoder().decode(keyPublico.getBytes(StandardCharsets.UTF_8)),
                    AES_KEY
            );

            SecretKeySpec hmacKey = new SecretKeySpec(
                    Base64.getDecoder().decode(hashPulico.getBytes(StandardCharsets.UTF_8)),
                    ALGO_HMAC
            );

            int macLength = obtainHmacLength(hmacKey);

            byte[] payload =
                    Base64.getDecoder().decode(
                            encryptedText.getBytes(StandardCharsets.UTF_8)
                    );

            if (payload.length < IV_SIZE + macLength) {
                throw new IllegalArgumentException(
                        "Invalid encrypted payload"
                );
            }

            int cipherTextLength = payload.length - macLength;

            byte[] iv = Arrays.copyOf(payload, IV_SIZE);

            byte[] cipherText = Arrays.copyOfRange(
                    payload,
                    IV_SIZE,
                    cipherTextLength
            );

            byte[] ivCipherText = concatenateBytes(iv, cipherText);

            byte[] receivedHmac = Arrays.copyOfRange(
                    payload,
                    cipherTextLength,
                    payload.length
            );

            byte[] calculatedHmac =
                    generateHmac(hmacKey, ivCipherText);

            if (!Arrays.equals(receivedHmac, calculatedHmac)) {
                throw new SecurityException("HMAC validation failed");
            }

            Cipher cipher =
                    Cipher.getInstance("AES/CBC/PKCS5PADDING");

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    aesKey,
                    new IvParameterSpec(iv)
            );

            byte[] plainText = cipher.doFinal(cipherText);

            return new String(
                    plainText,
                    StandardCharsets.UTF_8
            );

        } catch (Exception exp) {
            exp.printStackTrace();
            return "ERRORMESSAGE:ElektraEncryptionUtility-decryptAESHMac:Failed to decrypt";
        }
    }

    public static String decryptSecurityValue(String encryptedValue) {
        return decryptAESHMac(
                encryptedValue,
                KEY_PUBLICO,
                HASH_PUBLICO
        );
    }

    public static String getKeyPublico() {
        return KEY_PUBLICO;
    }

    public static String getHashPublico() {
        return HASH_PUBLICO;
    }

    public static int obtainHmacLength(SecretKeySpec key)
            throws Exception {

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);

        return hmac.getMacLength();
    }

    public static byte[] generateHmac(
            SecretKeySpec key,
            byte[] hmacInput)
            throws Exception {

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);

        return hmac.doFinal(hmacInput);
    }

    public static byte[] concatenateBytes(
            byte[] first,
            byte[] second) {

        byte[] concatBytes =
                new byte[first.length + second.length];

        System.arraycopy(
                first,
                0,
                concatBytes,
                0,
                first.length
        );

        System.arraycopy(
                second,
                0,
                concatBytes,
                first.length,
                second.length
        );

        return concatBytes;
    }

    public static byte[] generateInitializationVector() {

        byte[] iv = new byte[IV_SIZE];

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        return iv;
    }
}
