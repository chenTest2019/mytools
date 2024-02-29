package chen.tools;

import com.alibaba.fastjson2.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class LicenseUtil {
    private final String separator="-";
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final RSAKeyAndCertificateGenerator rsaKeyAndCertificateGenerator
            = new RSAKeyAndCertificateGenerator();

    public String getActiveCode(String basePath,String licenseeName, String expireDate){
        License license = getLicense(licenseeName, expireDate);
        try {
            return getActiveCode(basePath+ File.separator+RSAKeyAndCertificateGenerator.CRT_FILE,
                    basePath+ File.separator+RSAKeyAndCertificateGenerator.KEY_FILE, license);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private String getActiveCode(String certFile, String keyFile,String licenseeName, String expireDate){
        License license = getLicense(licenseeName, expireDate);
        try {
            return getActiveCode(certFile, keyFile, license);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * 生成licenseId
     * @return
     */
    private String getLicenseId() {
        return RandomStringUtils.randomAlphabetic(10).toUpperCase();
    }
    private License getLicense(String licenseeName, String expireDate){
        License license =  License.builder().build();
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

    private String getActiveCode(String certFile, String keyFile, License license)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            IOException, SignatureException, CertificateException {

        byte[] certBytes = rsaKeyAndCertificateGenerator.readPem(certFile);
        String certFullStr = rsaKeyAndCertificateGenerator.readPemFullStr(certFile);
        String certStr = BASE64_ENCODER.encodeToString(certBytes);
        byte[] privateKeyBytes = rsaKeyAndCertificateGenerator.readPem(keyFile);

        //PKCS#8
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        PrivateKey priKey= keyFactory.generatePrivate(pkcs8KeySpec);


        String licenseId = license.getLicenseId();
        String licenseJsonStr = JSONObject.toJSONString(license);
        byte[] licenseBytes = licenseJsonStr.getBytes(StandardCharsets.UTF_8);

        Signature privateSignature = Signature.getInstance("SHA1withRSA");
        privateSignature.initSign(priKey);
        privateSignature.update(licenseBytes);
        byte[] signature = privateSignature.sign();

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certFullStr.getBytes()));
        Signature publicSignature = Signature.getInstance("SHA1withRSA");
        publicSignature.initVerify(x509Certificate.getPublicKey());
        publicSignature.update(licenseBytes);
        if (!publicSignature.verify(signature)) {
            throw new RuntimeException("signature verify error");
        }
        return licenseId + separator + BASE64_ENCODER.encodeToString(licenseBytes) +
                separator + BASE64_ENCODER.encodeToString(signature) + separator + certStr;
    }
}