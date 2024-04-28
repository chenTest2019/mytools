package chen.tools.generator;

import chen.tools.License;
import chen.tools.Product;
import chen.tools.ProductEnum;
import com.alibaba.fastjson2.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static chen.tools.generator.CertificateGenerator.*;



public class LicenseGenerator {
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();

    public static void main(String[] args) throws IOException {
        String basePath = "E:\\ideame";
        var chen = getActiveCode(basePath, "chen", "2060-05-01");
        Files.writeString(Paths.get(basePath, "idea","activeCode.txt"), chen);
        System.out.println(chen);
    }
    public static String getActiveCode(String basePath, String licenseeName, String expireDate) {

        License license = getLicense(licenseeName, expireDate);
        try {
            return getActiveCode(basePath + File.separator + CertificateGenerator.CRT_FILE,
                    basePath + File.separator + CertificateGenerator.KEY_FILE, license);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 生成licenseId
     *
     * @return
     */
    private static String getLicenseId() {
        return RandomStringUtils.randomAlphabetic(10).toUpperCase();
    }

    private static License getLicense(String licenseeName, String expireDate) {
        License license = License.builder().build();
        license.setLicenseId(getLicenseId());
        license.setLicenseeName(licenseeName);
        List<Product> products = new ArrayList<>();
        ProductEnum[] values = ProductEnum.values();
        for (ProductEnum value : values) {
            Product product = new Product();

            product.setCode(value.getCode());
            product.setExtend(true);
            product.setFallbackDate(expireDate);
            product.setPaidUpTo(expireDate);

            products.add(product);
        }
        license.setProducts(products);
        return license;
    }

    private static String getActiveCode(String certFile, String keyFile, License license)
            throws Exception {

        X509Certificate cert = loadX509CertificateFromFile(certFile);
        byte[] certBytes = cert.getEncoded();
        String certStr = BASE64_ENCODER.encodeToString(certBytes);
        PrivateKey priKey = loadPrivateKeyFromPEMFile(keyFile, "RSA");


        String licenseId = license.getLicenseId();
        String licenseJsonStr = JSONObject.toJSONString(license);
        byte[] licenseBytes = licenseJsonStr.getBytes(StandardCharsets.UTF_8);

        Signature privateSignature = Signature.getInstance("SHA1withRSA");
        privateSignature.initSign(priKey);
        privateSignature.update(licenseBytes);
        byte[] signature = privateSignature.sign();

        Signature publicSignature = Signature.getInstance("SHA1withRSA");
        publicSignature.initVerify(cert.getPublicKey());
        publicSignature.update(licenseBytes);
        if (!publicSignature.verify(signature)) {
            throw new RuntimeException("signature verify error");
        }
        return String.join("-",licenseId,
                BASE64_ENCODER.encodeToString(licenseBytes),
                BASE64_ENCODER.encodeToString(signature),
                certStr);
    }

}
