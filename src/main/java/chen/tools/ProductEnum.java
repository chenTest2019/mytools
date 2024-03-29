package chen.tools;

import lombok.Getter;


@Getter
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
    //https://plugins.jetbrains.com/plugin/8286-sequencediagram/pricing#tabs
    Sequencediagram("PSEQUENCEDIAGRA"),
    CodeWithMe("PCWMP");
    private final String code;

    ProductEnum(String code) {
        this.code = code;
    }
}
