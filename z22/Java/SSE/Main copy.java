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

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        
        Random random = new Random();
        int AES_KEY_SIZE = 128;
        SecretKey AESKey = AES.keyGeneration(AES_KEY_SIZE);
        
        // 测试多个关键词数量
        int[] keywordsNumSet = {16384};
        int[] fileNum = {16384};
        int[] kSet = {10, 20, 30};
        // 添加搜索次数集合
        int[] searchTimesSet = {1, 10, 20, 30, 40};
        
        // 创建二维数组存储不同参数组合下的密文集大小
        double[][] encryptedSize = new double[keywordsNumSet.length][fileNum.length];
        // 修改为三维数组：[kSet索引][fileNum索引][searchTimesSet索引]
        double[][][] searchTimesByCount = new double[kSet.length][fileNum.length][searchTimesSet.length];
        double[][] updateTime = new double[kSet.length][fileNum.length];
        
        // 第一层循环：测试不同的关键词数量
        for(int keywordsIndex = 0; keywordsIndex < keywordsNumSet.length; keywordsIndex++) {
            int keywordsNum = keywordsNumSet[keywordsIndex];
            System.out.println("测试关键词数量: " + keywordsNum);
            
            // 生成对应数量的关键词
            String[] keywords = Data.keywordsGenerate(keywordsNum);
            
            // 第二层循环：测试不同的k值
            for(int q = 0; q < kSet.length; q++) {
                int k = kSet[q];
                
                // 第三层循环：测试不同的文件数量
                for(int i = 0; i < fileNum.length; i++) {
                    
                    String[] identities = Data.idsGenerate(fileNum[i]);
                    int idLength = (int) Math.ceil(Math.log(fileNum[i])*1.0/Math.log(2));
                                
                    SSE3 sse = new SSE3(keywords, idLength, fileNum[i], AES_KEY_SIZE, AESKey);
                                
                    Map<String, byte[]> DictW = sse.setup();
                    
                    // 计算密文集大小（字节）
                    long dictSize = calculateDictSize(DictW);
                    // 转换为MB
                    double dictSizeMB = dictSize / (1024.0 * 1024.0);
                    encryptedSize[keywordsIndex][i] = dictSizeMB;
                    
                    // 选择一个随机关键词进行搜索和更新测试
                    String testKeyword = keywords[random.nextInt(keywordsNum)];
                    System.out.println("测试关键词: " + testKeyword);
                    
                    // 先执行一些更新操作来确保有搜索结果
                    double Time1 = 0.0;
                    for(int j = 0; j < 100; j++) {
                        double t1 = System.currentTimeMillis();
                        DictW = sse.updateProcess(testKeyword, k, identities[j], 1, DictW);
                        Time1 = Time1 + System.currentTimeMillis() - t1;
                    }
                    updateTime[q][i] = Time1/100;
                    
                    // 第四层循环：测试不同的搜索次数
                    for(int searchIdx = 0; searchIdx < searchTimesSet.length; searchIdx++) {
                        int searchTimes = searchTimesSet[searchIdx];
                        
                        // 记录搜索时间
                        double totalSearchTime = 0.0;
                        for(int run = 0; run < 10; run++) { // 每种搜索次数重复测试10次取平均
                            double startTime = System.currentTimeMillis();
                            
                            // 连续执行指定次数的搜索
                            for(int s = 0; s < searchTimes; s++) {
                                DictW = sse.searchProcess(testKeyword, k, DictW);
                            }
                            
                            totalSearchTime += System.currentTimeMillis() - startTime;
                        }
                        
                        // 计算平均搜索时间
                        searchTimesByCount[q][i][searchIdx] = totalSearchTime / 10;
                        
                        System.out.println("k=" + k + ", 文件数量=" + fileNum[i] + 
                                ", 搜索次数=" + searchTimes + 
                                "; 平均耗时:" + searchTimesByCount[q][i][searchIdx] + "ms");
                    }
                    
                    // 重新计算完成所有操作后的密文集大小
                    dictSize = calculateDictSize(DictW);
                    dictSizeMB = dictSize / (1024.0 * 1024.0);
                    encryptedSize[keywordsIndex][i] = dictSizeMB;
                    
                    System.out.println("字典实际字节数: " + dictSize + " bytes");
                    System.out.println("关键词数量=" + keywordsNum + ", k=" + k + ", 文件数量=" + fileNum[i] + 
                            "; 更新时间:" + updateTime[q][i] + 
                            "ms; 密文集大小:" + String.format("%.2f", dictSizeMB) + "MB");
                }
            }
        }
        
        // 打印结果汇总
        System.out.println("\n========== 结果汇总 ==========");
        
        // 打印密文集大小汇总
        System.out.println("\n密文集大小汇总 (MB):");
        System.out.print("关键词数量/文件数量\t");
        for(int i = 0; i < fileNum.length; i++) {
            System.out.print(fileNum[i] + "\t");
        }
        System.out.println();
        
        for(int keywordsIndex = 0; keywordsIndex < keywordsNumSet.length; keywordsIndex++) {
            System.out.print(keywordsNumSet[keywordsIndex] + "\t\t");
            for(int j = 0; j < fileNum.length; j++) {
                System.out.print(String.format("%.2f", encryptedSize[keywordsIndex][j]) + "\t");
            }
            System.out.println();
        }
        
        // 打印搜索时间汇总
        System.out.println("\n搜索时间汇总 (ms):");
        for(int i = 0; i < kSet.length; i++) {
            System.out.println("k = " + kSet[i] + ":");
            
            for(int searchIdx = 0; searchIdx < searchTimesSet.length; searchIdx++) {
                System.out.println("搜索次数 = " + searchTimesSet[searchIdx] + ":");
                System.out.print("文件数量\t");
                for(int j = 0; j < fileNum.length; j++) {
                    System.out.print(fileNum[j] + "\t");
                }
                System.out.println();
                System.out.print("搜索时间\t");
                for(int j = 0; j < fileNum.length; j++) {
                    System.out.print(String.format("%.2f", searchTimesByCount[i][j][searchIdx]) + "\t");
                }
                System.out.println();
            }
            System.out.println();
        }
        
        // 打印更新时间汇总
        System.out.println("\n更新时间汇总 (ms):");
        for(int i = 0; i < kSet.length; i++) {
            System.out.println("k = " + kSet[i] + ":");
            System.out.print("文件数量\t");
            for(int j = 0; j < fileNum.length; j++) {
                System.out.print(fileNum[j] + "\t");
            }
            System.out.println();
            System.out.print("更新时间\t");
            for(int j = 0; j < fileNum.length; j++) {
                System.out.print(String.format("%.2f", updateTime[i][j]) + "\t");
            }
            System.out.println();
        }
    }
    
    /**
     * 计算密文集大小（字节）
     */
    private static long calculateDictSize(Map<String, byte[]> dictW) {
        if (dictW == null) return 0;
        
        long totalSize = 0;
        
        // 计算Map中所有key和value的大小总和
        for (Map.Entry<String, byte[]> entry : dictW.entrySet()) {
            // key的大小（字符串）
            totalSize += entry.getKey().length() * 2; // Java中每个字符占2字节
            
            // value的大小（字节数组）
            if (entry.getValue() != null) {
                totalSize += entry.getValue().length;
            }
        }
        
        return totalSize;
    }
}