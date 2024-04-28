package chen.tools.request;

import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.UUID;

public abstract class AbstractRequest<Response> {
    public static final String AUTH_TOKEN_HEADER_NAME = "Authorization";
    private long salt;
    private String machineId;
    private String hostName;
    private String userName;
    private String productCode;
    private boolean isSecure;
    private String ip;
    private int clientVersion;
    private String buildNumber;
    private Map<String, String> headers;


    public AbstractRequest() {
        this.clientVersion = 1;
    }

    protected AbstractRequest(long salt, String productCode, @NotNull UserIdentification userIdentification) {
        this(salt, productCode, userIdentification.getMachineId(), userIdentification.getHostName(), userIdentification.getUserName());
    }

    protected AbstractRequest(long salt, String productCode, String machineId, String hostName, String userName) {
        this.clientVersion = 1;
        this.salt = salt;
        this.productCode = productCode;
        this.machineId = machineId;
        this.hostName = hostName;
        this.userName = userName;
    }

    public long getSalt() {
        return this.salt;
    }

    public void setSalt(long salt) {
        this.salt = salt;
    }

    public String getMachineId() {
        return this.machineId;
    }

    public void setMachineId(String machineId) {
        this.machineId = machineId;
    }

    public String getHostName() {
        return this.hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    /** @deprecated */
    @Deprecated
    public String getProductFamilyId() {
        return this.productCode;
    }

    /** @deprecated */
    @Deprecated
    public void setProductFamilyId(String productFamilyId) {
        this.productCode = productFamilyId;
    }

    public String getProductCode() {
        return this.productCode;
    }

    public void setProductCode(String productCode) {
        this.productCode = productCode;
    }

    public boolean isSecure() {
        return this.isSecure;
    }

    public void setSecure(boolean isSecure) {
        this.isSecure = isSecure;
    }

    public String getIp() {
        return this.ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public int getClientVersion() {
        return this.clientVersion;
    }

    public void setClientVersion(int clientVersion) {
        this.clientVersion = clientVersion;
    }

    public abstract String getActionName();

    public String getBuildNumber() {
        return this.buildNumber;
    }

    public void setBuildNumber(String buildNumber) {
        this.buildNumber = buildNumber;
    }

    public String getAuthToken() {
        return this.headers != null ? (String)this.headers.get("Authorization") : null;
    }

    public void setAuthToken(String authToken) {
        this.headers = authToken != null ? Map.of("Authorization", authToken) : null;
    }

    public Map<String, String> getHeaders() {
        return this.headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? Map.copyOf(headers) : null;
    }



    public String getPropertyValueString(String propertyName, Object propertyValue) {
        return propertyValue == null ? "N/A" : propertyValue.toString();
    }

    public static final class UserIdentification {
        private final String machineId;
        private final String machineId2 = UUID.randomUUID().toString();
        private final String hostName;
        private final String userName;

        public UserIdentification(String machineId, String hostName, String userName) {
            this.machineId = machineId;
            this.hostName = hostName;
            this.userName = userName;
        }

        public String getMachineId() {
            return this.machineId;
        }

        public String getMachineId2() {
            return this.machineId2;
        }

        public String getHostName() {
            return this.hostName;
        }

        public String getUserName() {
            return this.userName;
        }
    }
}
