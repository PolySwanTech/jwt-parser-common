package org.pst.parser;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {
    public static RSAPublicKey loadPublicKey(String path) throws Exception {
        byte[] keyBytes;
        if (path.startsWith("classpath:")) {
            String resourcePath = path.replace("classpath:", "");
            try (InputStream is = KeyUtils.class.getClassLoader().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    throw new IllegalArgumentException("Resource not found: " + resourcePath);
                }
                keyBytes = is.readAllBytes();
            }
        } else {
            keyBytes = Files.readAllBytes(Paths.get(path));
        }
        String key = new String(keyBytes, StandardCharsets.UTF_8)
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }
}
