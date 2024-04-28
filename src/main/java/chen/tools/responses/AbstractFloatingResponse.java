package chen.tools.responses;

public class AbstractFloatingResponse extends AbstractResponse {
    private String serverLease;
    private String leaseSignature;
    private String serverUid;
    private String confirmationStamp;
    private String authorizationClientId;
    private String authorizationUrl;
    private String codeExchangeUrl;

    public AbstractFloatingResponse() {
    }

    public AbstractFloatingResponse(ResponseCode responseCode, String message, long salt) {
        super(responseCode, message, salt);
    }

    public String getServerLease() {
        return this.serverLease;
    }

    public void setServerLease(String serverLease) {
        this.serverLease = serverLease;
    }

    public String getLeaseSignature() {
        return this.leaseSignature;
    }

    public void setLeaseSignature(String leaseSignature) {
        this.leaseSignature = leaseSignature;
    }

    public String getServerUid() {
        return this.serverUid;
    }

    public void setServerUid(String serverUid) {
        this.serverUid = serverUid;
    }

    public String getConfirmationStamp() {
        return this.confirmationStamp;
    }

    public void setConfirmationStamp(String confirmationStamp) {
        this.confirmationStamp = confirmationStamp;
    }

    public String getAuthorizationClientId() {
        return this.authorizationClientId;
    }

    public void setAuthorizationClientId(String authorizationClientId) {
        this.authorizationClientId = authorizationClientId;
    }

    public String getAuthorizationUrl() {
        return this.authorizationUrl;
    }

    public void setAuthorizationUrl(String authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }

    public String getCodeExchangeUrl() {
        return this.codeExchangeUrl;
    }

    public void setCodeExchangeUrl(String codeExchangeUrl) {
        this.codeExchangeUrl = codeExchangeUrl;
    }
}
