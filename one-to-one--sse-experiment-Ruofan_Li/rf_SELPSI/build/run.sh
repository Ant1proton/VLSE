#!/bin/bash

# 编译程序
make

# 定义参数组合
file_nums=(5)
key_lens=(16)
max_bins_sizes=(16385*1.06)
search_keywords_nums=(10)
dataset_paths=("/Users/chenyuwei/Desktop/one-to-one--sse-experiment-Ruofan_Li/rf_SELPSI/data/data14_5")

# 创建输出目录
mkdir -p results

# 遍历所有参数组合
for file_num in "${file_nums[@]}"; do
    for key_len in "${key_lens[@]}"; do
        for max_bins_size in "${max_bins_sizes[@]}"; do
            for search_keywords_num in "${search_keywords_nums[@]}"; do
                for dataset_path in "${dataset_paths[@]}"; do
                    # 生成输出文件名
                    output_file="results/output_file_${file_num}_keylen_${key_len}_binsize_${max_bins_size}_keywords_${search_keywords_num}.txt"

                    # 运行程序并保存输出
                    ./main --file-num $file_num \
                           --key-len $key_len \
                           --max-bins-size $max_bins_size \
                           --search-keywords-num $search_keywords_num \
                           --dataset-path $dataset_path > "$output_file"

                    echo "测试完成: $output_file"
                done
            done
        done
    done
done
