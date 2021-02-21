package licensekey.generator.service;

import licensekey.generator.exception.PrivateKeyGenerationException;
import licensekey.generator.utils.Constants;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * This class loads the private key from a file and returns.
 *
 * @since 1.0.0
 */
public class PrivateKeyReader {

    /**
     * @return Private key
     * @throws PrivateKeyGenerationException which capture no file found exception, invalid algorithm exception and
     *                                       invalid key spec exception
     */
    public static PrivateKey getPrivateKey(String keyFileLocation) throws PrivateKeyGenerationException {

        byte[] keyBytes;
        try {
            keyBytes = Files.readAllBytes(Paths.get(keyFileLocation));
        } catch (IOException e) {
            throw new PrivateKeyGenerationException("Private key file not found", e);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new PrivateKeyGenerationException("Algorithm Invalid", e);
        }
        try {
            return keyFactory.generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            throw new PrivateKeyGenerationException("Invalid Key spec", e);
        }
    }
}
