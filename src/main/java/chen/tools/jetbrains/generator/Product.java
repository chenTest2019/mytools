package chen.tools.jetbrains.generator;


import lombok.Data;

@Data
public class Product {
    private String code;
    private String fallbackDate;
    private String paidUpTo;
    private boolean extend;
}
