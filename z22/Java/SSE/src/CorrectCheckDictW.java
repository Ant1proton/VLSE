import java.util.*;

public class CorrectCheckDictW {
    public static void main(String[] args) {
        MapToFile mf = new MapToFile();
        Map<String, String> DictW = mf.readObject();

        System.out.println("DictW集合大小: " + DictW.size());

        // 输出几条数据看看具体结构
        int count = 0;
        for (Map.Entry<String, String> entry : DictW.entrySet()) {
            System.out.println("Key: " + entry.getKey());
            System.out.println("Value: " + entry.getValue());
            if (++count >= 5) break;  // 看前5条数据即可
        }
    }
}
