import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Description GET FIST RSA encode password by original password
 * @author H3C_BMC
 */
public class Main {

    /**
     * Description main method
     * for example
     * @author H3C_BMC
     * @param args args
     */
    public static void main(String[] args) {
        // login_keypair Response
        String modulus =
            "008a200d9c329b1b338c3a586c024ae59f2e7cda9d3e8ccb8db39cc1b44d079dc3572062b0fbb60e4881c132cf88484f03375b48027ea30b4d26720bbfc4b30ac2419cebf90ba19aa044bb09f2eac6b085abd6976a44c28d36b2c3b5f1e30ef82597aef3858995da4144c6da94a4b9b72fa93cc8090368fcb5f17ca576810b2c17";
        String exponent = "010001";

        // original password
        String originalPwd = "Password@_";

        String encryptPwd = getFistPasswd(modulus, exponent, originalPwd);
        System.out.println(encryptPwd);

    }

    /**
     *
     * @param modulus login_keypair Response modulus
     * @param exponent login_keypair Response exponent
     * @param originalPwd original password
     * @return encryption password
     */
    private static String getFistPasswd(String modulus, String exponent, String originalPwd) {
        try {
            // 生成公钥
            BigInteger bigIntModulus = new BigInteger(modulus, 16);
            BigInteger bigIntPrivateExponent = new BigInteger(exponent, 16);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

            // use BouncyCastleProvider encrypt, default RSA, /None/NoPadding
            Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (null == provider) {
                Security.addProvider(new BouncyCastleProvider());
            }
            Cipher cipher = Cipher.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

            // output reverse password
            byte[] output = cipher.doFinal(StringUtils.reverse(originalPwd).getBytes(StandardCharsets.UTF_8));

            // hex encode output
            return new String(Hex.encodeHex(output));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
