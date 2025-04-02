import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

public class ECDHAESEncryption {
    private final byte[] aesKey;
    private final byte[] hmacKey;

    public ECDHAESEncryption(byte[] sharedSecret) throws NoSuchAlgorithmException {
        // Derive AES-256 key from sharedSecret using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] fullKey = sha256.digest(sharedSecret);

        // Split key: first 32 bytes for AES, last 32 bytes for HMAC
        this.aesKey = Arrays.copyOfRange(fullKey, 0, 32);
        this.hmacKey = Arrays.copyOfRange(fullKey, 32, 64);
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        // Generate random IV (12 bytes recommended for AES-GCM)
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);

        // Initialize AES-GCM cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        // Encrypt the message
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Compute HMAC
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKey hmacSecretKey = new SecretKeySpec(hmacKey, "HmacSHA256");
        hmac.init(hmacSecretKey);
        byte[] hmacValue = hmac.doFinal(plaintext);

        // Combine IV, ciphertext, and HMAC using ByteBuffer
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length + hmacValue.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        buffer.put(hmacValue);

        // Return the combined result as a byte[]
        return buffer.array(); // Return as byte[] instead of Base64 encoded string
    }

    public byte[] decrypt(byte[] encryptedMessage) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedMessage);

        // Extract IV
        byte[] iv = new byte[12];
        buffer.get(iv);

        // Extract ciphertext
        byte[] ciphertext = new byte[buffer.remaining() - 32];
        buffer.get(ciphertext);

        // Extract HMAC
        byte[] receivedHmac = new byte[32];
        buffer.get(receivedHmac);

        // Initialize AES-GCM cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        // Decrypt the message
        byte[] plaintext = cipher.doFinal(ciphertext);

        // Verify HMAC
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKey hmacSecretKey = new SecretKeySpec(hmacKey, "HmacSHA256");
        hmac.init(hmacSecretKey);
        byte[] computedHmac = hmac.doFinal(plaintext);

        if (!Arrays.equals(receivedHmac, computedHmac)) {
            throw new SecurityException("HMAC verification failed!");
        }

        return plaintext; // Convert decrypted byte[] back to String
    }
}
