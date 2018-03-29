
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;


public class AESEncryptor {
    private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";//AES/GCM/NoPadding
    public final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static AESEncryptor instance;
    private String alias_ = "classmate123";
    private KeyStore keyStore;

    private AESEncryptor() {
    }

    public static AESEncryptor getInstance() {
        if (instance == null) {
            instance = new AESEncryptor();
        }
        return instance;
    }

    public KeyStore initAndroidKeyStore(Context pContext) {
        try {
            if (keyStore == null) {
                keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
                keyStore.load(null);
                createNewKeys(pContext);
            }
        } catch (Exception e) {
            AppLog.errLog("AESEncrytion", "initAndroidKeyStore : " + e.getMessage());
        }
        return keyStore;
    }

    public String encrypt(String key, String cleartext) throws Exception {
        //AppLog.log("AESEncrytion", "encrypt+++ " + cleartext);
        if (cleartext == null || cleartext.trim().length()==0||cleartext.isEmpty()) {
            return "";
        }
        return encryptString(alias_, cleartext);
    }


    public String decrypt(String key, String encryptedValue) throws Exception {
        //AppLog.log("AESEncrytion", "encryptedValue+++ " + encryptedValue);
        if (encryptedValue == null || encryptedValue.trim().length()==0||encryptedValue.isEmpty()) {
            return "";
        }
        return decryptString(alias_, encryptedValue);
    }


    public void createNewKeys(Context pContext) {
        String alias = alias_;
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                AlgorithmParameterSpec spec = null;
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    spec = new KeyPairGeneratorSpec.Builder(pContext)
                            // You'll use the alias later to retrieve the key.  It's a key for the key!
                            .setAlias(alias)
                            // The subject used for the self-signed certificate of the generated pair
                            .setSubject(new X500Principal("CN=" + alias))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();
                }else {
                    // On Android M or above, use the KeyGenparameterSpec.Builder and specify permitted
                    // properties  and restrictions of the key.
                    spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setCertificateSubject(new X500Principal("CN=" + alias))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                            .setCertificateSerialNumber(BigInteger.ONE)
                            .setCertificateNotBefore(start.getTime())
                            .setCertificateNotAfter(end.getTime())
                            .build();
                }
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);
                generator.initialize(spec);
                KeyPair keyPair = generator.generateKeyPair();
               // AppLog.log("AESEncrytion", "createNewKeys keyPair.getPrivate(): " + keyPair.getPrivate());
               // AppLog.log("AESEncrytion", "createNewKeys keyPair.getPublic(): " + keyPair.getPublic());
            } else {
                AppLog.log("AESEncrytion", "KeyStore already containsAlias alias: " + keyStore.containsAlias(alias));
            }
        } catch (Exception e) {
            AppLog.errLog("AESEncrytion", "createNewKeys: " + e.getMessage());
        }
        //refreshKeys();
    }


    public String encryptString(String alias, String initialText) {
        try {
            //AppLog.log("AESEncrytion", "initialText+++ " + initialText);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
            //AppLog.log("AESEncrytion", "encryptString keyPair.getPublic(): " + publicKey.getEncoded());
            // RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher input = Cipher.getInstance(CIPHER_TYPE);
            input.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted=input.doFinal(initialText.getBytes("UTF-8"));

//            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
//            cipherOutputStream.write(initialText.getBytes("UTF-8"));
//            cipherOutputStream.close();
//            byte[] vals = outputStream.toByteArray();
//            AppLog.log("AESEncrytion", "decryptString+++ " + Base64.encodeToString(vals, Base64.DEFAULT));

            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        } catch (Exception e) {
            AppLog.errLog("AESEncrytion", "encryptString " + e.getMessage() + " occured");
        }
        return "";
    }


    public String decryptString(String alias, String cipherText) {
        try {
            //AppLog.log("AESEncrytion", "cipherText : " + cipherText);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            // RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            //AppLog.log("AESEncrytion", "decryptString keyPair.getPrivate(): " + privateKey.getEncoded());

            Cipher output = Cipher.getInstance(CIPHER_TYPE);
            output.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted=output.doFinal(Base64.decode(cipherText, Base64.DEFAULT));

//            CipherInputStream cipherInputStream = new CipherInputStream(
//                    new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
//            ArrayList<Byte> values = new ArrayList<>();
//            int nextByte;
//            while ((nextByte = cipherInputStream.read()) != -1) {
//                values.add((byte) nextByte);
//            }
//            byte[] bytes = new byte[values.size()];
//            for (int i = 0; i < bytes.length; i++) {
//                bytes[i] = values.get(i).byteValue();
//            }
            String finalText = new String(decrypted, 0, decrypted.length, "UTF-8");
           // AppLog.log("AESEncrytion", "decryptString : " + finalText);
            return finalText;
        } catch (Exception e) {
            AppLog.errLog("AESEncrytion", "decryptString:: " + e.getMessage() + " occured");
        }
        return "";
    }

    public boolean isKeysAvail() throws KeyStoreException {
        return keyStore.containsAlias(alias_);
    }

    public void deleteKey() throws KeyStoreException {
        keyStore.deleteEntry(alias_);
    }


}
