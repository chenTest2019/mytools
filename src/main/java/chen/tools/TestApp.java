package chen.tools;

import lombok.extern.slf4j.Slf4j;

public class TestApp {
    public static void main(String[] args) throws Exception{
        System.out.println("main");
    }

    public static void test(String filePath) throws Exception {
        System.out.println("test :"+filePath);
    }

    public  void test2(String filePath) throws Exception {

        System.out.println("test2:"+filePath);
    }
}
