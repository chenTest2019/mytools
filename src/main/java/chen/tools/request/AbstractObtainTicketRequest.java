package chen.tools.request;

public abstract class AbstractObtainTicketRequest<Response> extends AbstractRequest<Response> {
    public static final int BUILD_DATE_CUTOFF = 20000000;
    protected int versionNumber;
    protected int buildDate = Integer.MAX_VALUE;
    private int versionOrBuildDate;
    private boolean haveVersionAndBuildDate;
    private String edition;
    private boolean sendBuildDateAsVersionToOldServers;

    public AbstractObtainTicketRequest() {
    }

    public AbstractObtainTicketRequest(long salt, String productCode, String machineId, String hostName, String userName, int version, int buildDate, boolean sendBuildDateAsVersionToOldServers) {
        super(salt, productCode, machineId, hostName, userName);
        this.versionNumber = version;
        this.buildDate = buildDate;
        this.sendBuildDateAsVersionToOldServers = sendBuildDateAsVersionToOldServers;
        this.haveVersionAndBuildDate = true;
    }

    public int getVersionNumber() {
        if (this.haveVersionAndBuildDate) {
            return this.versionNumber;
        } else {
            return this.versionOrBuildDate >= 20000000 ? 0 : this.versionOrBuildDate;
        }
    }

    public void setVersionNumber(int versionNumber) {
        this.versionNumber = versionNumber;
        this.haveVersionAndBuildDate = true;
    }

    public int getBuildDate() {
        if (this.haveVersionAndBuildDate) {
            return this.buildDate;
        } else {
            return this.versionOrBuildDate >= 20000000 ? this.versionOrBuildDate : 0;
        }
    }

    public void setBuildDate(int buildDate) {
        this.buildDate = buildDate;
        this.haveVersionAndBuildDate = true;
    }

    public String getEdition() {
        return this.edition;
    }

    public void setEdition(String edition) {
        this.edition = edition;
    }

    public int getVersion() {
        return this.sendBuildDateAsVersionToOldServers ? this.buildDate : this.versionNumber;
    }

    public void setVersion(int version) {
        this.versionOrBuildDate = version;
    }
}
