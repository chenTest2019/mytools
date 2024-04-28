package chen.tools.responses;

public class AbstractResponse {
    private long salt;
    private ResponseCode responseCode;
    private Action action;
    private String message;
    private String signature;
    private long validationPeriod;
    private long validationDeadlinePeriod;


    public String getSignature() {
        return this.signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public long getValidationPeriod() {
        return this.validationPeriod;
    }

    public void setValidationPeriod(long validationPeriod) {
        this.validationPeriod = validationPeriod;
    }

    public long getValidationDeadlinePeriod() {
        return this.validationDeadlinePeriod;
    }

    public void setValidationDeadlinePeriod(long validationDeadlinePeriod) {
        this.validationDeadlinePeriod = validationDeadlinePeriod;
    }

    public AbstractResponse() {
        this.action = Action.NONE;
        this.validationDeadlinePeriod = -1L;
    }

    public AbstractResponse(ResponseCode responseCode, String message, long salt) {
        this.action = Action.NONE;
        this.validationDeadlinePeriod = -1L;
        this.salt = salt;
        this.responseCode = responseCode;
        this.setMessage(message);
    }

    public long getSalt() {
        return this.salt;
    }

    public ResponseCode getResponseCode() {
        return this.responseCode;
    }

    public Action getAction() {
        return this.action;
    }

    public String getMessage() {
        return this.message;
    }

    public void setResponseCode(ResponseCode responseCode) {
        this.responseCode = responseCode;
    }

    public void setAction(Action action) {
        this.action = action;
    }

    public void setSalt(long salt) {
        this.salt = salt;
    }

    public final void setMessage(String message) {
        this.message = message != null ? message.replace('\n', ' ').replace('\r', ' ') : null;
    }

    public String getPropertyValueString(String propertyName, Object propertyValue) {
        return propertyValue == null ? "N/A" : propertyValue.toString();
    }
}
