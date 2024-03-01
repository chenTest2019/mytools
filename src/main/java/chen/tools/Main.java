package chen.tools;

import org.apache.commons.io.FileUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Base64;


public class Main {
    public static void main(String[] args) throws Exception {

        String basePath = "E:\\ideame";
        RSAKeyAndCertificateGenerator rsaKeyAndCertificateGenerator = new RSAKeyAndCertificateGenerator();

//        String configBasePath = "E:\\ideame" + File.separator + "idea" + File.separator + "config-jetbrains" + File.separator;
//        String generate = rsaKeyAndCertificateGenerator.saveFile(basePath, ChronoUnit.YEARS, 10);
//        System.out.println(generate);
//
//        boolean b = rsaKeyAndCertificateGenerator.genPowerPluginConfigFile(basePath, configBasePath);
//        System.out.println(b);

        LicenseUtil licenseUtil = new LicenseUtil();
        String activeCode = licenseUtil.getActiveCode(basePath, "chen", "2099-12-12");
        FileUtils.write(new File(basePath + File.separator + "activeCode.txt"), activeCode, StandardCharsets.UTF_8);
        System.out.println(activeCode);

        //test(basePath + File.separator + "activeCode.txt");

    }

    public static void test(String filePath) throws Exception {
        String activeCode = FileUtils.readFileToString(new File(filePath), StandardCharsets.UTF_8);
        String[] licenseParts = activeCode.split("-");
        String licensePartBase64 = licenseParts[1];
        final String signatureBase64 = licenseParts[2];
        final String certBase64 = licenseParts[3];

        System.out.println(new String(Base64.getDecoder().decode(licensePartBase64), StandardCharsets.UTF_8));

        byte[] binaryCertificate = Base64.getDecoder().decode(certBase64);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
        System.out.println(cert);


    }
}