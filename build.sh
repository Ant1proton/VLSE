#!/bin/bash

# 清理旧的构建文件
echo "清理旧的构建文件..."
rm -rf CMakeCache.txt CMakeFiles

# 强制使用 Xcode 系统编译器（避免 Homebrew LLVM 兼容性问题）
echo "配置 CMake（使用 Xcode 系统编译器）..."
CC=/usr/bin/clang CXX=/usr/bin/clang++ /opt/homebrew/bin/cmake .

# 编译项目
echo "编译项目..."
make -j$(sysctl -n hw.ncpu)

echo "✅ 编译完成！"
echo "可执行文件："
ls -lh main main_triple test_triple_vf 2>/dev/null || echo "部分目标可能未构建成功"
