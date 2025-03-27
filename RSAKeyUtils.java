import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RSAKeyUtils {

	// Function 1: Generate an RSA Key Pair
	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048); // You can choose a key size (e.g., 2048 bits)
		return keyGen.generateKeyPair();
	}

	// Function 2: Save the Public Key to a File
	//TODO passar para fileutils
	public static void savePublicKey(PublicKey publicKey, String fileName) throws IOException {
		// Get the encoded format of the public key
		byte[] keyBytes = publicKey.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(fileName)) {
			fos.write(keyBytes);
		}
	}

	// Function 3: Read the Public Key from a File
	// TODO passar para fileutils
	public static PublicKey readPublicKey(String fileName) throws Exception {
		// Read the key bytes from the file
		byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
		// Create a key specification from the encoded bytes
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		// Create a KeyFactory for RSA and generate the PublicKey
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(spec);
	}

	// Encrypts the given message using the RSA private key.
	public static byte[] encryptWithPublicKey(byte[] message, PublicKey publicKey) throws Exception {
		// Using RSA with ECB mode and PKCS#1 padding.
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(message);
	}

	// Decrypts the given message using the RSA public key.
	public static byte[] decryptWithPrivateKey(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encryptedMessage);
	}

	public static PublicKey convertToPublicKey(byte[] keyBytes) throws Exception {
		// Create a key specification from the byte array
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		// Get a KeyFactory for RSA
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		// Generate the PublicKey from the specification
		return keyFactory.generatePublic(spec);
	}

	public static byte[] convertPublicKeyToBytes(PublicKey publicKey) {
		// The getEncoded() method returns the key in its default X.509 encoded format.
		return publicKey.getEncoded();
	}

	public static byte[] encryptData(byte[] data, PublicKey publicKey) throws Exception {
		// Create and initialize the RSA cipher for encryption with PKCS#1 padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		// Maximum chunk size: 245 bytes for a 2048-bit key with PKCS#1 padding
		int maxChunkSize = 245;
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		// Process each chunk
		for (int i = 0; i < data.length; i += maxChunkSize) {
			int chunkSize = Math.min(maxChunkSize, data.length - i);
			byte[] chunk = Arrays.copyOfRange(data, i, i + chunkSize);
			byte[] encryptedChunk = cipher.doFinal(chunk);
			outputStream.write(encryptedChunk);
		}

		return outputStream.toByteArray();
	}

	public static byte[] decryptData(byte[] encryptedData, PrivateKey privateKey) throws Exception {
		// Create and initialize the RSA cipher for decryption with PKCS#1 padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		// Each encrypted block is 256 bytes (for a 2048-bit RSA key)
		int encryptedChunkSize = 256;
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		// Process each chunk
		for (int i = 0; i < encryptedData.length; i += encryptedChunkSize) {
			int chunkSize = Math.min(encryptedChunkSize, encryptedData.length - i);
			byte[] chunk = Arrays.copyOfRange(encryptedData, i, i + chunkSize);
			byte[] decryptedChunk = cipher.doFinal(chunk);
			outputStream.write(decryptedChunk);
		}

		return outputStream.toByteArray();
	}
}
