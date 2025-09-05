import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception {
        
        Random random = new Random();
        int AES_KEY_SIZE = 128;
        SecretKey AESKey = AES.keyGeneration(AES_KEY_SIZE);
        
        // 测试多个关键词数量，与文件数量一一对应
        int[] keywordsNumSet = {16384, 32768, 65536, 131072, 262144};
        //int[] keywordsNumSet = {10000};
        // 确保数组长度相同，一一对应
        int[] fileNumSet = {5000, 5000, 5000, 5000, 5000};
        //int[] fileNumSet = {10000};
        //int[] kSet = {10, 20, 30};
        int[] kSet = {10};
        // 添加搜索次数集合
        int[] searchTimesSet = {1, 10, 20, 30, 40};
        
        // 创建数组存储不同参数组合下的密文集大小
        double[] encryptedSize = new double[keywordsNumSet.length];
        double[] initialSize = new double[keywordsNumSet.length]; // 记录初始密文大小
        double[] updateSize = new double[keywordsNumSet.length];  // 记录更新后密文大小
        // 修改为三维数组：[kSet索引][测试组合索引][searchTimesSet索引]
        double[][][] searchTimesByCount = new double[kSet.length][keywordsNumSet.length][searchTimesSet.length];
        double[][] updateTime = new double[kSet.length][keywordsNumSet.length];
        // 添加初始化时间数组
        double[][] setupTime = new double[kSet.length][keywordsNumSet.length];
        
        // 使用单个循环，让关键词数量和文件数量一一对应
        for(int index = 0; index < keywordsNumSet.length; index++) {
            int keywordsNum = keywordsNumSet[index];
            int fileNum = fileNumSet[index];
            
            System.out.println("测试组合: 关键词数量=" + keywordsNum + ", 文件数量=" + fileNum);
            
            // 生成对应数量的关键词
            String[] keywords = Data.keywordsGenerate(keywordsNum);
            
            // 测试不同的k值
            for(int q = 0; q < kSet.length; q++) {
                int k = kSet[q];
                
                String[] identities = Data.idsGenerate(fileNum);
                int idLength = (int) Math.ceil(Math.log(fileNum)*1.0/Math.log(2));
                            
                SSE sse = new SSE(keywords, idLength, fileNum, AES_KEY_SIZE, AESKey);
                
                // 计时开始
                double setupStartTime = System.currentTimeMillis();
                            
                // 执行setup操作
                Map<String, BigInteger> DictW = sse.setup();
                
                // 计时结束
                double setupEndTime = System.currentTimeMillis();
                setupTime[q][index] = setupEndTime - setupStartTime;
                
                System.out.println("初始化时间: " + setupTime[q][index] + "ms");
                
                // 计算密文集大小（字节）
                long dictSize = calculateDictSize(DictW);
                // 转换为MB
                double dictSizeMB = dictSize / (1024.0 * 1024.0);
                initialSize[index] = dictSizeMB;  // 保存初始大小
                System.out.println("初始密文集大小: " + dictSizeMB + " MB");
                /*
                // 为更新操作选择一个固定的关键词
                String updateKeyword = keywords[random.nextInt(keywordsNum)];
                System.out.println("更新关键词: " + updateKeyword);
                
                // 先执行一些更新操作来确保有搜索结果
                double Time1 = 0.0;
                for(int j = 0; j < 100; j++) {
                    double t1 = System.currentTimeMillis();
                    DictW = sse.updateProcess(updateKeyword, k, identities[j], 1, DictW);
                    Time1 = Time1 + System.currentTimeMillis() - t1;
                }
                updateTime[q][index] = Time1/100;
                
                // 更新后计算密文大小
                dictSize = calculateDictSize(DictW);
                dictSizeMB = dictSize / (1024.0 * 1024.0);
                updateSize[index] = dictSizeMB;  // 保存更新后大小
                System.out.println("100次更新后密文集大小: " + dictSizeMB + " MB");
                */
                // 测试不同的搜索次数
                for(int searchIdx = 0; searchIdx < searchTimesSet.length; searchIdx++) {
                    int searchTimes = searchTimesSet[searchIdx];
                    
                    // 记录搜索时间
                    double totalSearchTime = 0.0;
                    for(int run = 0; run < 10; run++) { // 每种搜索次数重复测试10次取平均
                        double startTime = System.currentTimeMillis();
                        
                        // 连续执行指定次数的搜索，每次使用不同的随机关键词
                        for(int s = 0; s < searchTimes; s++) {
                            // 每次搜索选择一个新的随机关键词
                            String searchKeyword = keywords[random.nextInt(keywordsNum)];
                            DictW = sse.searchProcess(searchKeyword, k, DictW);
                        }
                        
                        totalSearchTime += System.currentTimeMillis() - startTime;
                    }
                    
                    // 计算平均搜索时间
                    searchTimesByCount[q][index][searchIdx] = totalSearchTime / 10;
                    
                    System.out.println("k=" + k + ", 关键词/文件数量=" + keywordsNum + 
                            ", 搜索次数=" + searchTimes + 
                            "; 平均耗时:" + searchTimesByCount[q][index][searchIdx] + "ms");
                }
                
                // 重新计算完成所有操作后的密文集大小
                dictSize = calculateDictSize(DictW);
                dictSizeMB = dictSize / (1024.0 * 1024.0);
                encryptedSize[index] = dictSizeMB;
                
                System.out.println("字典实际字节数: " + dictSize + " bytes");
                System.out.println("k=" + k + ", 关键词/文件数量=" + keywordsNum + 
                      //  "; 更新时间:" + updateTime[q][index] + 
                        "ms; 最终密文集大小:" + String.format("%.2f", dictSizeMB) + "MB");
            }
        }
        
        // 打印结果汇总
        System.out.println("\n========== 结果汇总 ==========");
        
        // 打印初始化时间汇总
        System.out.println("\n初始化时间汇总 (ms):");
        for(int i = 0; i < kSet.length; i++) {
            System.out.println("k = " + kSet[i] + ":");
            System.out.println("关键词/文件数量\t初始化时间(ms)");
            for(int index = 0; index < keywordsNumSet.length; index++) {
                System.out.println(keywordsNumSet[index] + "\t\t" + 
                                 String.format("%.2f", setupTime[i][index]));
            }
            System.out.println();
        }
        
        // 打印密文集大小汇总
        System.out.println("\n密文集大小汇总 (MB):");
        System.out.println("关键词/文件数量\t初始大小\t更新后大小\t最终大小");
        for(int index = 0; index < keywordsNumSet.length; index++) {
            System.out.println(keywordsNumSet[index] + "\t\t" + 
                             String.format("%.2f", initialSize[index]) + "\t\t" +
                             String.format("%.2f", updateSize[index]) + "\t\t" +
                             String.format("%.2f", encryptedSize[index]));
        }
        
        // 打印搜索时间汇总
        System.out.println("\n搜索时间汇总 (ms):");
        for(int i = 0; i < kSet.length; i++) {
            System.out.println("k = " + kSet[i] + ":");
            
            for(int searchIdx = 0; searchIdx < searchTimesSet.length; searchIdx++) {
                System.out.println("搜索次数 = " + searchTimesSet[searchIdx] + ":");
                System.out.println("关键词/文件数量\t搜索时间(ms)");
                for(int index = 0; index < keywordsNumSet.length; index++) {
                    System.out.println(keywordsNumSet[index] + "\t\t" + 
                                     String.format("%.2f", searchTimesByCount[i][index][searchIdx]));
                }
                System.out.println();
            }
        }
        
        // 打印更新时间汇总
       /* System.out.println("\n更新时间汇总 (ms):");
        for(int i = 0; i < kSet.length; i++) {
            System.out.println("k = " + kSet[i] + ":");
            System.out.println("关键词/文件数量\t更新时间(ms)");
            for(int index = 0; index < keywordsNumSet.length; index++) {
                System.out.println(keywordsNumSet[index] + "\t\t" + 
                                 String.format("%.2f", updateTime[i][index]));
            }
            System.out.println();
        }*/
    }
    
    /**
     * 计算密文集大小（字节）- 修改为处理BigInteger类型的值
     */
    private static long calculateDictSize(Map<String, BigInteger> dictW) {
        if (dictW == null) return 0;
        
        long totalSize = 0;
        
        // 计算Map中所有key和value的大小总和
        for (Map.Entry<String, BigInteger> entry : dictW.entrySet()) {
            // key的大小（字符串）
            totalSize += entry.getKey().length() * 2; // Java中每个字符占2字节
            
            // value的大小（BigInteger）
            if (entry.getValue() != null) {
                // BigInteger的字节表示
                byte[] bytes = entry.getValue().toByteArray();
                totalSize += bytes.length;
            }
        }
        
        return totalSize;
    }
}