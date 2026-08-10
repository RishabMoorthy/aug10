package com.sv;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;


public class ElektraEncryption {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        String publicKeyString = "";
        String privateKeyString = "";

        PublicKey publicKey = getPublicKeyFromString(publicKeyString);
        PrivateKey privateKey = getPrivateKeyFromString(privateKeyString);

        String originalMessage = "Sindhu";

        String encryptedMessage = encrypt(originalMessage, publicKey);
        System.out.println("Encrypted Text (Base64): " + encryptedMessage);
        String decryptedMessage = decrypt(encryptedMessage, privateKey);
        System.out.println("Decrypted Text (Base64): " + decryptedMessage);
    }

    public static String encrypt(String mensaje, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        byte[] bytesCifrados = cipher.doFinal(mensaje.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytesCifrados);
    }


    public static PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PrivateKey getPrivateKeyFromString(String privateKeyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static String decrypt(String encryptedMessageBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] encryptedBiytes = Base64.getDecoder().decode(encryptedMessageBase64);
        byte[] decryptedBytes = cipher.doFinal(encryptedBiytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static String decryptAESHMac(String encryptedText, String keyPublico, String hashPulico) {
        String decryptedText = null;
        try {

            SecretKeySpec aesKey = new SecretKeySpec(Base64.getDecoder().decode(keyPublico.getBytes(ENCODING_UTF8)),AES_KEY);
            SecretKeySpec hmacKey = new SecretKeySpec(Base64.getDecoder().decode(hashPulico.getBytes(ENCODING_UTF8)),ALGO_HMAC);

            int macLength = obtainHmacLength(hmacKey);

            byte[] iv_cipherText_hmac = Base64.getDecoder().decode(encryptedText.getBytes(ENCODING_UTF8));
            int cipherTextLength = iv_cipherText_hmac.length - macLength;


            byte[] iv = Arrays.copyOf(iv_cipherText_hmac, IV_SIZE);
            byte[] cipher_Text = Arrays.copyOfRange(iv_cipherText_hmac, IV_SIZE, cipherTextLength);
            byte[] iv_cipherText = concatenateBytes(iv,cipher_Text);
            byte[] receivedHmac = Arrays.copyOfRange(iv_cipherText_hmac, iv_cipherText.length,iv_cipherText_hmac.length);
            byte[] calculatedHmac = generateHmac(hmacKey, iv_cipherText);
            System.out.println(Arrays.equals(receivedHmac, calculatedHmac));
            if (Arrays.equals(receivedHmac, calculatedHmac)) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

                cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                byte[] plainText = cipher.doFinal(cipher_Text);
                decryptedText = new String(plainText, ENCODING_UTF8);
            }

            return decryptedText ;

        } catch (Exception exp) {
            exp.printStackTrace();
            return "ERRORMESSAGE:ElektraEncryptionUtility -decryptAESHMac:Failed to decrypt key or hash reqiured to encrypt appropriate Direct to Account API request to Elektra";
        }
    }

    public static int obtainHmacLength(SecretKeySpec key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.getMacLength();
    }

    public static byte[] generateHmac(SecretKeySpec key, byte[] hmacInput) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.doFinal(hmacInput);
    }

    public static byte[] concatenateBytes(byte[] first, byte[] second) {
        byte[] concatBytes = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatBytes, 0, first.length);
        System.arraycopy(second, 0, concatBytes, first.length, second.length);
        return concatBytes;
    }

    public static byte[] generateInitializationVector() {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }
}
