import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.HashSet;
import java.util.Set;

public class MapToFile {

    // 可配置的常量
    private static final int NUM_PAIRS = 16384; // 数据对数目
    private static final int WORD_LENGTH = 6;  // 关键词长度
    private static final int MAX_TAG_ID = 10000; // 标签最大ID

    // 生成随机字符串作为关键词
    private String generateRandomWord(int length) {
        Random random = new Random();
        StringBuilder word = new StringBuilder();
        for (int i = 0; i < length; i++) {
            char randomChar = (char) ('a' + random.nextInt(26)); // 生成a-z之间的随机字符
            word.append(randomChar);
        }
        return word.toString();
    }

    // 生成随机标签
    private String generateRandomTag(int maxTagId) {
        Random random = new Random();
        int tagId = random.nextInt(maxTagId) + 1; // 生成1到maxTagId之间的随机数字
        return "doc_id" + tagId;
    }

    // 写入对象到文件
    public void writeObject(Map<String, String> map) {
        try {
            FileOutputStream outStream = new FileOutputStream("/Users/chenyuwei/Desktop/paper_code/比较的论文/z22/Java/SSE/src/DictW.txt");
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outStream);
            objectOutputStream.writeObject(map);
            outStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 从文件中读取对象
    public Map<String, String> readObject() {
        Map<String, String> map = new HashMap<>();
        try {
            FileInputStream freader = new FileInputStream("/Users/chenyuwei/Desktop/paper_code/比较的论文/z22/Java/SSE/src/DictW.txt");
            ObjectInputStream objectInputStream = new ObjectInputStream(freader);
            map = (HashMap<String, String>) objectInputStream.readObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return map;
    }

    // 批量生成数据对
    public Map<String, String> generateData(int numPairs, int wordLength, int maxTagId) {
        Map<String, String> map = new HashMap<>();
        Set<String> generatedWords = new HashSet<>();
        Random random = new Random();

        for (int i = 0; i < numPairs; i++) {
            String word;
            do {
                word = generateRandomWord(wordLength);
            } while (generatedWords.contains(word)); // 确保关键词不重复

            generatedWords.add(word);
            String tag = generateRandomTag(maxTagId);
            map.put(word, tag);
        }

        return map;
    }

    public static void main(String[] args) {
        MapToFile mf = new MapToFile();

        // 生成数据对
        Map<String, String> data = mf.generateData(NUM_PAIRS, WORD_LENGTH, MAX_TAG_ID);

        // 写入文件
        mf.writeObject(data);

        // 从文件读取并打印
        Map<String, String> readData = mf.readObject();
        for (String key : readData.keySet()) {
            System.out.println(key + " -> " + readData.get(key));
        }
    }
}
