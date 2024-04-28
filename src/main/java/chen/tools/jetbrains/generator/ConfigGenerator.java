package chen.tools.jetbrains.generator;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.atomic.AtomicBoolean;

import static chen.tools.jetbrains.generator.CertificateGenerator.CRT_FILE;
import static chen.tools.jetbrains.generator.CertificateGenerator.JetProfile_CA;


public class ConfigGenerator {
    private static  BigInteger   PUBLIC_KEY_MODULUS;
    static {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(JetProfile_CA.getBytes()));
            RSAPublicKey publicKey = ((RSAPublicKey) x509Certificate.getPublicKey());
            PUBLIC_KEY_MODULUS=publicKey.getModulus();
        } catch (CertificateException e) {
            System.out.println(e);
        }
    }
    public static void main(String[] args) throws Exception {
        System.out.println(generate("E:\\ideame"));
    }

    public static boolean generate(String path) throws Exception {
        var cert = CertificateGenerator.loadX509CertificateFromFile(Paths.get(path,CRT_FILE).toString());
        if (cert != null) {

            var signature = cert.getSignature();
            var sigAlgName = cert.getSigAlgName();
            System.out.println("sigAlgName:"+sigAlgName);
            var publicKey = (RSAPublicKey)cert.getPublicKey();

            BigInteger x=new BigInteger(1, signature);

            BigInteger y=publicKey.getPublicExponent();

            var z = PUBLIC_KEY_MODULUS;

            var r =x.modPow(y,publicKey.getModulus());

            var s = Files.readString(Paths.get(path, "idea","config.json"), StandardCharsets.UTF_8);
            JSONObject allConfig = JSONObject.parseObject(s);
            var bigIntegerConfig = allConfig.getJSONObject("BigIntegerConfig");
            var jsonArray = bigIntegerConfig.getJSONArray("records");
            AtomicBoolean hasRecords = new AtomicBoolean(false);
            var iterator = jsonArray.iterator();
            while (iterator.hasNext()){
                var obj = iterator.next();
                JSONObject json = (JSONObject) obj;
                var x1 = json.getBigInteger("x");
                var y1 = json.getBigInteger("y");
                var z1 = json.getBigInteger("z");
                var r1 = json.getBigInteger("result");
                // 检查配置项是否有误
                if(x1.modPow(y1,publicKey.getModulus()).equals(r1)){
                    if(x1.equals(x)&&y1.equals(y)&&z1.equals(z)){
                        hasRecords.set(true);
                    }
                }else{
                    System.out.println("remove:\n"+json);
                    iterator.remove();
                }
            };


            if (!hasRecords.get()) {
                JSONObject object=new JSONObject();
                object.put("x", x.toString());
                object.put("y",y.toString());
                object.put("z", z.toString());
                object.put("result", r.toString());
                jsonArray.add(object);

                Files.writeString(Paths.get(path, "idea", "config.json"), allConfig.toString(JSONWriter.Feature.PrettyFormat));
                System.out.println("add:\n"+object.toString(JSONWriter.Feature.PrettyFormat));
                return true;
            }

        }
        return false;
    }


}
