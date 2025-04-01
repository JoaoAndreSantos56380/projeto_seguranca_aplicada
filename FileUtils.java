import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;

public class FileUtils {
	// Function 2: Save the Public Key to a File
	public static void savePublicKey(PublicKey publicKey, String fileName) throws IOException {
		// Get the encoded format of the public key
		byte[] keyBytes = publicKey.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(fileName)) {
			fos.write(keyBytes);
		}
	}

	// Function 2: Save the Public Key to a File
	public static void saveClientPIN(SecretKey key, String fileName) throws IOException {
		// Get the encoded format of the public key
		byte[] keyBytes = key.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(fileName)) {
			fos.write(keyBytes);
		}
	}

	// Function 3: Read the Public Key from a File
	public static PublicKey readPublicKey(String fileName) {
		// Read the key bytes from the file
		PublicKey pk = null;
		try {
			byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
			// Create a key specification from the encoded bytes
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			// Create a KeyFactory for RSA and generate the PublicKey
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			pk = keyFactory.generatePublic(spec);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pk;
	}
}
