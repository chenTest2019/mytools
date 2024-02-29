package chen.tools;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class XYZR {


    public static void main(String[] args)  throws Exception{
        String basePath="E:\\ideame";
        String crtPath=basePath+ File.separator+RSAKeyAndCertificateGenerator.CRT_FILE;
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert =  (X509Certificate)certificateFactory.generateCertificate(new FileInputStream(crtPath));

        // x：证书的签名密文
        System.out.println("x：证书的签名密文");
        System.out.println(new BigInteger(1,cert.getSignature()));
        System.out.println();

        // y：证书指数 固定65537
        System.out.println("y：证书指数 固定65537");
        System.out.println(new BigInteger("65537"));
        System.out.println();


        // z：内置根证书的公钥
        X509Certificate rootCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(RSAKeyAndCertificateGenerator.JET_ROOT_CA.getBytes(StandardCharsets.UTF_8)));
        RSAPublicKey publicKey = (RSAPublicKey)rootCertificate.getPublicKey();
        System.out.println("z：内置根证书的公钥");
        System.out.println(publicKey.getModulus());
        System.out.println();


        //r : 对DER 编码的证书信息(即来自该证书的tbsCertificate) 进行sha265摘要计算，计算的结果转换为ASN1格式数据，ASN1格式数据再进行填充得到的
        int modBits = ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength();
        int emLen = (modBits + 7) / 8;
        // sha256 进行摘要
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] tbsCertificateBytes = cert.getTBSCertificate();
        byte[] digestBytes = digest.digest(tbsCertificateBytes);
        // DER-encoded
        byte[] digestAlgo = new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, (byte) 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        byte[] digestInfo = new byte[digestAlgo.length + digestBytes.length];
        System.arraycopy(digestAlgo, 0, digestInfo, 0, digestAlgo.length);
        System.arraycopy(digestBytes, 0, digestInfo, digestAlgo.length, digestBytes.length);

        // 补齐
        byte[] ps = new byte[emLen - digestInfo.length - 3];
        Arrays.fill(ps, (byte) 0xFF);

        //构造最终的结果
        byte[] encoded = new byte[emLen];
        encoded[0] = 0x00;
        encoded[1] = 0x01;
        System.arraycopy(ps, 0, encoded, 2, ps.length);
        encoded[ps.length + 2] = 0x00;
        System.arraycopy(digestInfo, 0, encoded, ps.length + 3, digestInfo.length);

        System.out.println("r : 对DER 编码的证书信息(即来自该证书的tbsCertificate) 进行sha265摘要计算，计算的结果转换为ASN1格式数据，ASN1格式数据再进行填充得到的");
        System.out.println(new BigInteger(encoded));

    }


}