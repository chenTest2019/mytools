package chen.tools;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.rsa.RSAPadding;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

import javax.crypto.BadPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.TemporalUnit;
import java.util.Date;

public class RSAKeyAndCertificateGenerator {
    public static final String KEY_FILE = "private.key";
    public static final String CRT_FILE = "public.crt";
    private static final String JET_PUBLIC_KEY =
            "860106576952879101192782278876319243486072481962999610484027161162448933268423045647258145695082284265933019120714643752088997312766689988016808929265129401027490891810902278465065056686129972085119605237470899952751915070244375173428976413406363879128531449407795115913715863867259163957682164040613505040314747660800424242248055421184038777878268502955477482203711835548014501087778959157112423823275878824729132393281517778742463067583320091009916141454657614089600126948087954465055321987012989937065785013284988096504657892738536613208311013047138019418152103262155848541574327484510025594166239784429845180875774012229784878903603491426732347994359380330103328705981064044872334790365894924494923595382470094461546336020961505275530597716457288511366082299255537762891238136381924520749228412559219346777184174219999640906007205260040707839706131662149325151230558316068068139406816080119906833578907759960298749494098180107991752250725928647349597506532778539709852254478061194098069801549845163358315116260915270480057699929968468068015735162890213859113563672040630687357054902747438421559817252127187138838514773245413540030800888215961904267348727206110582505606182944023582459006406137831940959195566364811905585377246353";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static X500Name getX500Name(String data) {
        X500NameBuilder rootIssueMessage = new X500NameBuilder(
                BCStrictStyle.INSTANCE);
        rootIssueMessage.addRDN(BCStyle.CN, data);
//        rootIssueMessage.addRDN(BCStyle.O, O);
//        rootIssueMessage.addRDN(BCStyle.L, L);
//        rootIssueMessage.addRDN(BCStyle.ST, ST);
//        rootIssueMessage.addRDN(BCStyle.C, C);
//        rootIssueMessage.addRDN(BCStyle.OU, OU);
        return rootIssueMessage.build();
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

    private KeyPair getKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(keySize, random);
        return keyGen.generateKeyPair();

    }

    public boolean genPowerPluginConfigFile(String basePath, String configBasePath)
            throws CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException,
            BadPaddingException, InvalidKeyException {
        String certFile = basePath + File.separator + CRT_FILE;
        String confFile = configBasePath + File.separator + "power.conf";
        genPowerPluginConfig(certFile, confFile);
        return true;
    }

    private void genPowerPluginConfig(String certFilePath, String configFilePath)
            throws CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException,
            BadPaddingException, InvalidKeyException {
        String certContent = readPemFullStr(certFilePath);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certContent.getBytes()));
        RSAPublicKey publicKey = ((RSAPublicKey) x509Certificate.getPublicKey());
        String exponent = publicKey.getPublicExponent().toString(10);
        byte[] bytes = encodeSignature(x509Certificate.getTBSCertificate(), publicKey.getModulus().bitLength());
        String powerConfig = "[Result]\nEQUAL," + new BigInteger(1, x509Certificate.getSignature()).toString(10) + "," + exponent +
                "," + JET_PUBLIC_KEY + "->" + new BigInteger(1, bytes).toString(10);
        FileWriter fileWriter = new FileWriter(configFilePath);
        fileWriter.write(powerConfig);
        fileWriter.close();
    }

    private byte[] encodeSignature(byte[] values, int keySize)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException,
            BadPaddingException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(values);
        byte[] bytes = messageDigest.digest();
        RSAPadding padding = RSAPadding.getInstance(RSAPadding.PAD_BLOCKTYPE_1, (keySize + 7) >> 3, null);
        DerOutputStream out = new DerOutputStream();
        new AlgorithmId(AlgorithmId.SHA256_oid).encode(out);
        out.putOctetString(bytes);
        DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        return padding.pad(result.toByteArray());
    }

    public String saveFile(String basePath, TemporalUnit temporalUnit, int expirationTime) throws Exception {

        KeyPair keyPair = getKeyPair(4096);
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis() / 1000);


        X509v3CertificateBuilder certificateBuilder = getCertificateBuilder(serialNumber, aPublic, temporalUnit, expirationTime);
        //SHA256WithRSAEncryption
        //ContentSigner contentSigner=new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(aPrivate);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(aPrivate);

        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider("BC");
        X509Certificate certificate = certificateConverter.getCertificate(certificateBuilder.build(contentSigner));
        saveToPemFile(basePath + File.separator + CRT_FILE, "CERTIFICATE", certificate.getEncoded());
        saveToPemFile(basePath + File.separator + KEY_FILE, "PRIVATE KEY", aPrivate.getEncoded());
        return certificate.toString();
    }

    private X509v3CertificateBuilder getCertificateBuilder(BigInteger serialNumber, PublicKey publicKey, TemporalUnit temporalUnit, int expirationTime) {

        LocalDate now = LocalDate.now();
        LocalDate end = now.plus(expirationTime, temporalUnit);
        //CN=My Self Signed Certificate
        X500Name issuer = getX500Name("My Self Signed Certificate");
        X500Name subject = issuer; // 自签名，所以issuer和subject相同
        X500Name issuerName = getX500Name("JetProfile CA");

        return new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                localDateToDate(now),
                localDateToDate(end),
                issuer,
                publicKey
        );
    }

    private void saveToPemFile(String outputPath, String type, byte[] data) throws IOException {
        PemObject pemObject = new PemObject(type, data);
        FileWriter fileWriter = new FileWriter(outputPath);
        PemWriter pemWriter = new PemWriter(fileWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
    }

    public  byte[] readPem(String outputPath) throws IOException {
        PemReader pemReader = new PemReader(new FileReader(outputPath));
        PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    public String readPemFullStr(String outputPath) throws IOException {
        PemReader pemReader = new PemReader(new FileReader(outputPath));
        PemObject pemObject = pemReader.readPemObject();
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }

}
