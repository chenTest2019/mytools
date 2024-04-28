package chen.tools.request;


import chen.tools.responses.ObtainTicketResponse;
import org.jetbrains.annotations.NotNull;

public class ObtainTicketRequest extends AbstractObtainTicketRequest<ObtainTicketResponse> {
    public static final String ACTION_NAME = "obtainTicket.action";

    public ObtainTicketRequest() {
    }

    public ObtainTicketRequest(long salt, @NotNull String productFamilyId, int version, int buildDate, boolean sendBuildDateAsVersionToOldServers, @NotNull String machineId, String hostName, String userName) {
        super(salt, productFamilyId, machineId, hostName, userName, version, buildDate, sendBuildDateAsVersionToOldServers);
    }

    public String getActionName() {
        return "obtainTicket.action";
    }
}
