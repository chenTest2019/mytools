package chen.tools.jetbrains.generator;


import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;

/**
 * 在探讨公钥和私钥的编码格式及其文件格式时，我们需要明确区分以下几个相关但具有不同语境的概念：
 * 私钥的编码格式： 私钥的编码格式是指私钥数据的内部二进制表示规则。此类格式重点关注如何将私钥的数学参数（如RSA的两个大素数p和q、欧拉函数值phi(n)、私钥指数d等）按照特定的数据结构、编码规则和可能的加密算法进行编码，以适应计算机存储和处理。典型的私钥编码格式包括：
 * PKCS#8: 一种标准化私钥编码格式，适用于多种公钥加密算法（如RSA、DSA、EC等）。使用ASN.1语法描述私钥信息，并采用DER编码规则进行二进制序列化，可以是明文（未加密）或使用密码加密。
 * PKCS#1 (RSA-specific): 针对RSA私钥的专用编码格式，描述了私钥的二进制表示，包括模数n、私钥指数d等参数。
 * 公钥的编码格式： 公钥的编码格式同样是指公钥数据的内部二进制表示规则。这类格式专注于公钥的数学参数（如RSA的模数n和公钥指数e）如何按照特定的数据结构、编码规则和算法标识进行编码，以适应计算机存储和处理。典型公钥编码格式包括：
 * X.509 (DER encoded): 遵循X.509标准，使用DER编码公钥参数和算法标识符，通常用于数字证书或独立公钥交换。
 * SubjectPublicKeyInfo (SPKI): 作为X.509标准的一部分，定义公钥的ASN.1结构，包含公钥算法标识和参数，常用于不含证书其他元信息的公钥表示。
 * PKCS#1 (RSA-specific): 专门针对RSA公钥，定义其模数和公钥指数的二进制编码。
 * 私钥/公钥文件的格式： 私钥和公钥的文件格式则涵盖了密钥数据在文件系统中的完整表现形式，不仅包括密钥的编码格式，还涉及文件封装方式、扩展名、头部和尾部标识、文本编码（如Base64）、附加元数据以及文件权限设置等。文件格式旨在确保密钥文件在操作系统、文件传输协议和编程接口间的互操作性。常见的私钥和公钥文件格式包括：
 * PEM (Privacy-Enhanced Mail): 一种文本编码格式，使用Base64对DER编码的密钥数据进行封装，以-----BEGIN [PRIVATE|PUBLIC] KEY-----和-----END [PRIVATE|PUBLIC] KEY-----标识，便于文本文件、邮件或编辑器中的存储与交换。
 * SSH Public Key Format: SSH协议特有的公钥文件格式，以ssh-rsa（或其它算法标识）开头，随后跟公钥参数，常用于SSH身份验证和密钥交换。
 * JSON Web Key (JWK): 基于JSON的密钥表示格式，以JSON对象封装密钥类型、算法、参数及可选元数据，适于Web服务和API的密钥交换。
 * 综上所述，私钥和公钥的编码格式分别关注密钥数据的内在编码逻辑，而私钥/公钥文件的格式则囊括了密钥数据在文件系统中的完整封装与存储形态。在讨论私钥或公钥的编码格式时，应聚焦于密钥数据的内在编码规则，而非诸如PEM这样的文件封装格式。
 */

public class CertificateGenerator {
    public static final String KEY_FILE = "private-Test.key";
    public static final String CRT_FILE = "public-Test.crt";
    public static final String JetProfile_CA = """
                -----BEGIN CERTIFICATE-----
                MIIFOzCCAyOgAwIBAgIJANJssYOyg3nhMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNV
                BAMMDUpldFByb2ZpbGUgQ0EwHhcNMTUxMDAyMTEwMDU2WhcNNDUxMDI0MTEwMDU2
                WjAYMRYwFAYDVQQDDA1KZXRQcm9maWxlIENBMIICIjANBgkqhkiG9w0BAQEFAAOC
                Ag8AMIICCgKCAgEA0tQuEA8784NabB1+T2XBhpB+2P1qjewHiSajAV8dfIeWJOYG
                y+ShXiuedj8rL8VCdU+yH7Ux/6IvTcT3nwM/E/3rjJIgLnbZNerFm15Eez+XpWBl
                m5fDBJhEGhPc89Y31GpTzW0vCLmhJ44XwvYPntWxYISUrqeR3zoUQrCEp1C6mXNX
                EpqIGIVbJ6JVa/YI+pwbfuP51o0ZtF2rzvgfPzKtkpYQ7m7KgA8g8ktRXyNrz8bo
                iwg7RRPeqs4uL/RK8d2KLpgLqcAB9WDpcEQzPWegbDrFO1F3z4UVNH6hrMfOLGVA
                xoiQhNFhZj6RumBXlPS0rmCOCkUkWrDr3l6Z3spUVgoeea+QdX682j6t7JnakaOw
                jzwY777SrZoi9mFFpLVhfb4haq4IWyKSHR3/0BlWXgcgI6w6LXm+V+ZgLVDON52F
                LcxnfftaBJz2yclEwBohq38rYEpb+28+JBvHJYqcZRaldHYLjjmb8XXvf2MyFeXr
                SopYkdzCvzmiEJAewrEbPUaTllogUQmnv7Rv9sZ9jfdJ/cEn8e7GSGjHIbnjV2ZM
                Q9vTpWjvsT/cqatbxzdBo/iEg5i9yohOC9aBfpIHPXFw+fEj7VLvktxZY6qThYXR
                Rus1WErPgxDzVpNp+4gXovAYOxsZak5oTV74ynv1aQ93HSndGkKUE/qA/JECAwEA
                AaOBhzCBhDAdBgNVHQ4EFgQUo562SGdCEjZBvW3gubSgUouX8bMwSAYDVR0jBEEw
                P4AUo562SGdCEjZBvW3gubSgUouX8bOhHKQaMBgxFjAUBgNVBAMMDUpldFByb2Zp
                bGUgQ0GCCQDSbLGDsoN54TAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkq
                hkiG9w0BAQsFAAOCAgEAjrPAZ4xC7sNiSSqh69s3KJD3Ti4etaxcrSnD7r9rJYpK
                BMviCKZRKFbLv+iaF5JK5QWuWdlgA37ol7mLeoF7aIA9b60Ag2OpgRICRG79QY7o
                uLviF/yRMqm6yno7NYkGLd61e5Huu+BfT459MWG9RVkG/DY0sGfkyTHJS5xrjBV6
                hjLG0lf3orwqOlqSNRmhvn9sMzwAP3ILLM5VJC5jNF1zAk0jrqKz64vuA8PLJZlL
                S9TZJIYwdesCGfnN2AETvzf3qxLcGTF038zKOHUMnjZuFW1ba/12fDK5GJ4i5y+n
                fDWVZVUDYOPUixEZ1cwzmf9Tx3hR8tRjMWQmHixcNC8XEkVfztID5XeHtDeQ+uPk
                X+jTDXbRb+77BP6n41briXhm57AwUI3TqqJFvoiFyx5JvVWG3ZqlVaeU/U9e0gxn
                8qyR+ZA3BGbtUSDDs8LDnE67URzK+L+q0F2BC758lSPNB2qsJeQ63bYyzf0du3wB
                /gb2+xJijAvscU3KgNpkxfGklvJD/oDUIqZQAnNcHe7QEf8iG2WqaMJIyXZlW3me
                0rn+cgvxHPt6N4EBh5GgNZR4l0eaFEV+fxVsydOQYo1RIyFMXtafFBqQl6DDxujl
                FeU3FZ+Bcp12t7dlM4E0/sS1XdL47CfGVj4Bp+/VbF862HmkAbd7shs7sDQkHbU=
                -----END CERTIFICATE-----
                """;

    public static void main(String[] args) throws Exception {
        var result = certificate("E:\\ideame");
        System.out.println(result);
    }

    private static Date localDateToDate(LocalDate localDate) {
        if (localDate == null) {
            return null;
        }

        // 将LocalDate转换为LocalDateTime（设置时间为当天的开始时间）
        LocalDateTime localDateTime = localDate.atStartOfDay();

        // 将LocalDateTime转换为ZonedDateTime，使用系统默认时区
        ZonedDateTime zonedDateTime = localDateTime.atZone(ZoneId.systemDefault());

        // 将ZonedDateTime转换为旧版的Date对象
        return Date.from(zonedDateTime.toInstant());
    }

    private static KeyPair getKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(keySize, random);
        return keyGen.generateKeyPair();

    }


    private static  String certificate(String basePath) throws Exception {
        String certPath=basePath+ File.separator + CRT_FILE;
        String privateKeyPath=basePath + File.separator + KEY_FILE;
        if (Files.exists(Paths.get(certPath)) && Files.exists(Paths.get(privateKeyPath))) {
            return "证书和私钥已存在";
        }
        var keyPair = getKeyPair(4096);
        var publicKey = keyPair.getPublic();
        var privateKey = keyPair.getPrivate();
        // 创建证书
        Certificate certificate = generateCertificate(publicKey, privateKey);
        var encoded = certificate.getEncoded();

        var s = saveToPemFile(certPath, encoded, PemType.CERTIFICATE);
        var s1 = saveToPemFile(privateKeyPath, privateKey.getEncoded(), PemType.PRIVATE_KEY);
        return "certPath:"+certPath+"\n"+"privateKeyPath:"+privateKeyPath;
    }
    public enum PemType  {
        CERTIFICATE("CERTIFICATE"),
        PRIVATE_KEY("PRIVATE KEY"),
        PUBLIC_KEY("PUBLIC KEY");

        private final String value;

        PemType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    public static String saveToPemFile(String filePath,byte[] encoded,PemType type) throws Exception {
        // 将DER编码转换为Base64编码的字符串
        String base64Cert = Base64.getEncoder().encodeToString(encoded);
        // 构建PEM格式的证书文本，包含BEGIN CERTIFICATE和END CERTIFICATE标签
        StringBuilder pemCertBuilder = new StringBuilder();
        if(type==PemType.PRIVATE_KEY){
            pemCertBuilder.append("-----BEGIN PRIVATE KEY-----\n");
        }else if(type==PemType.PUBLIC_KEY){
            pemCertBuilder.append("-----BEGIN PUBLIC KEY-----\n");
        }else if(type==PemType.CERTIFICATE){
            pemCertBuilder.append("-----BEGIN CERTIFICATE-----\n");
        }else{
            throw new Exception("type error");
        }
        pemCertBuilder.append(chunk(base64Cert, 64)); // 每行64个字符，符合PEM标准
        if(type==PemType.PRIVATE_KEY){
            pemCertBuilder.append("-----END PRIVATE KEY-----\n");
        }else if(type==PemType.PUBLIC_KEY){
            pemCertBuilder.append("-----END PUBLIC KEY-----\n");
        }else if(type==PemType.CERTIFICATE){
            pemCertBuilder.append("-----END CERTIFICATE-----\n");
        }else{
            throw new Exception("type error");
        }

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            // 将PEM格式的证书文本写入文件
            fos.write(pemCertBuilder.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IOException("Failed to save certificate to PEM file: " + filePath, e);
        }
        return filePath;
    }

    private static String chunk(String s, int chunkSize) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be positive");
        }
        StringBuilder sb = new StringBuilder();
        for (int start = 0, end = Math.min(start + chunkSize, s.length()); start < s.length(); start = end, end = Math.min(start + chunkSize, s.length())) {
            sb.append(s, start, end).append('\n');
        }
        return sb.toString();
    }


    public static PrivateKey loadPrivateKeyFromPEMFile(String filePath, String algorithm) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            StringBuilder privateKeyPem = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                if (line.startsWith("-----BEGIN PRIVATE KEY-----")) {
                    while (!(line = reader.readLine()).startsWith("-----END PRIVATE KEY-----")) {
                        privateKeyPem.append(line.trim());
                    }
                    break;
                }
            }

            // Remove any line breaks and decode the Base64 string
            byte[] encodedPrivateKey = Base64.getDecoder().decode(privateKeyPem.toString().replaceAll("\\s", ""));

            // Create a PKCS8EncodedKeySpec from the decoded bytes
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);

            // Use a KeyFactory to generate a PrivateKey object
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Exception("Failed to load private key from PEM file.", e);
        }
    }

    public static X509Certificate loadX509CertificateFromFile(String filePath) throws Exception {
        // 创建证书工厂
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // 从文件中加载证书
        FileInputStream fis = new FileInputStream(filePath);

        // 从证书中提取公钥
        return (X509Certificate) cf.generateCertificate(fis);
    }
    /**
     * 从x.509证书中读取公钥
     * @param filePath
     * @return
     * @throws Exception
     */
    public static PublicKey loadPublicKeyFromFile(String filePath) throws Exception {

        return loadX509CertificateFromFile(filePath).getPublicKey();
    }

    public static PublicKey loadPublicKeyFromPEMFile(String filePath,String algorithm) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            StringBuilder publicKeyPem = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                if (line.startsWith("-----BEGIN PUBLIC KEY-----")) {
                    while (!(line = reader.readLine()).startsWith("-----END PUBLIC KEY-----")) {
                        publicKeyPem.append(line.trim());
                    }
                    break;
                }
            }

            // Remove any line breaks and decode the Base64 string
            byte[] encodedPublicKey = Base64.getDecoder().decode(publicKeyPem.toString().replaceAll("\\s", ""));

            // Create an X509EncodedKeySpec from the decoded bytes
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);

            // Use a KeyFactory to generate a PublicKey object
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Exception("Failed to load public key from PEM file.", e);
        }
    }
    private static Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        // var dnName = new X500Principal("CN=JetBrains, OU=JetBrains, O=JetBrains, L=Moscow, ST=Moscow, C=RU");
        LocalDate now = LocalDate.now();

        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(localDateToDate(now), localDateToDate(now.plusYears(10))));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

        //System.out.println(Arrays.toString(Security.getProviders()));
        var bigInteger = new BigInteger(64, new SecureRandom());
        //System.out.println(bigInteger.toString(16));

        //var bytes = HexFormat.of().parseHex("65e0dd95");
        //bigInteger=new BigInteger(1,bytes);

        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(bigInteger));
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.SHA256_oid)));
        certInfo.set(X509CertInfo.SUBJECT, new X500Name("CN=My Self Signed Certificate"));
        certInfo.set(X509CertInfo.ISSUER, new X500Name("CN=JetProfile CA"));

        X509CertImpl x509Cert = new X509CertImpl(certInfo);
        // 使用私钥对证书进行签名
        x509Cert.sign(privateKey, "SHA256withRSA");
        //x509Cert.set();
        return x509Cert;
    }
}
