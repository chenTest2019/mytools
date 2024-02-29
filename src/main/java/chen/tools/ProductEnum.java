package chen.tools;

import lombok.Data;


public enum ProductEnum {
    PhpStorm("PS"),
    Pycharm("PC"),
    AIAssistant("AIP"),
    Goland("GO"),
    Webstorm("WS"),
    Rubymine("RM"),
    Dataspell("DS"),
    Elasticsearch("PELASTICSEARCH"),
    RestfulFastRequestAPIBuddy("PFASTREQUEST"),
    Idea("II"),
    Clion("CL"),
    Rider("RD"),
    Datagrip("DB"),
    Appcode("AC"),
    CodeWithMe("PCWMP");
    private String code;
    ProductEnum(String code) {
        this.code = code;
    }
    public String getCode() {
        return code;
    }
}
