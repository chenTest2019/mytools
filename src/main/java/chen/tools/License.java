package chen.tools;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;

import java.util.List;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class License {
    private String licenseId;
    private String licenseeName;
    @Builder.Default
    private String assigneeName="assigneeName";
    @Builder.Default
    private String assigneeEmail="assigneeEmail";
    @Builder.Default
    private String licenseRestriction="licenseRestriction";
    private boolean checkConcurrentUse;
    private List<Product> products;
    @Builder.Default
    private String metadata="0120230914PSAX000005";
    @Builder.Default
    private String hash= "TRIAL:-1635216578";
    @Builder.Default
    private int gracePeriodDays=7;
    private boolean autoProlongated;
    private boolean isAutoProlongated;
}
