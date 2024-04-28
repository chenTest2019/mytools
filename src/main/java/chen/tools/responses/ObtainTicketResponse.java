package chen.tools.responses;



import chen.tools.request.ObtainTicketRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class ObtainTicketResponse extends AbstractFloatingResponse {
    private String ticketId;
    private String ticketProperties;
    private long prolongationPeriod;

    public ObtainTicketResponse() {
    }

    public ObtainTicketResponse(String ticketId, ResponseCode responseCode, String ticketProperties, String message, long salt) {
        super(responseCode, message, salt);
        this.ticketId = ticketId;
        this.ticketProperties = ticketProperties;
    }

    public String getTicketId() {
        return this.ticketId;
    }

    public void setTicketId(String ticketId) {
        this.ticketId = ticketId;
    }

    public String getTicketProperties() {
        return this.ticketProperties;
    }

    public Map<String, String> parseTicketProperties() {
        HashMap var1 = new HashMap();
        StringTokenizer var2 = new StringTokenizer(this.ticketProperties, "\t", false);

        while (var2.hasMoreTokens()) {
            String var3 = var2.nextToken();
            String var4 = var3.substring(0, var3.indexOf("="));
            String var5 = var3.substring(var3.indexOf("=") + 1);
            var1.put(var4, var5);
        }

        return var1;
    }

    public void setTicketProperties(String ticketProperties) {
        this.ticketProperties = ticketProperties;
    }

    public long getProlongationPeriod() {
        return this.prolongationPeriod;
    }

    public void setProlongationPeriod(long prolongationPeriod) {
        this.prolongationPeriod = prolongationPeriod;
    }

    public static ObtainTicketResponse error(String message, ObtainTicketRequest request) {
        return new ObtainTicketResponse(null, ResponseCode.ERROR, "", message, request.getSalt());
    }
}
