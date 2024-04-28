package chen.tools;


import org.apache.commons.io.FileUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static chen.tools.generator.LicenseGenerator.getActiveCode;


public class Main {
    public static void main(String[] args) throws Exception {

        String basePath = "E:\\ideame";

        String activeCode =  getActiveCode(basePath, "chen", "2099-12-12");
        FileUtils.write(new File(basePath + File.separator + "activeCode-Test.txt"), activeCode, StandardCharsets.UTF_8);
        System.out.println(activeCode);

    }

    public static void test(String filePath) throws Exception {
        String activeCode = FileUtils.readFileToString(new File(filePath), StandardCharsets.UTF_8);
        String[] licenseParts = activeCode.split("-");
        final String licenseId= licenseParts[0];
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
