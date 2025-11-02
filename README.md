# VLSE 
### 依赖库
- **CMake** >= 3.10
- **C++14** 编译器支持
- **OpenSSL** 库
- **Crypto++** 库  
- **NTL** (Number Theory Library) 库
- **Xcode** 15.3

### 安装依赖 (macOS)
- **Vaccum filter**-
-  Paper Link: http://www.vldb.org/pvldb/vol13/p197-wang.pdf
-  Code Link: https://github.com/wuwuz/Vacuum-Filter
```bash
# 使用Homebrew安装依赖
brew install cmake openssl cryptopp ntl

# 或者使用MacPorts
sudo port install cmake openssl cryptopp ntl
```

### 安装依赖 (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install cmake build-essential libssl-dev libcrypto++-dev libntl-dev
```

## 编译和运行

### 1. 克隆项目

```bash
git clone git@github.com:Ant1proton/VLSE.git
cd VLSE
```

### 2. 编译项目

```bash
rm -rf CMakeCache.txt CMakeFiles && CC=/usr/bin/clang CXX=/usr/bin/clang++ /opt/homebrew/bin/cmake . && make -j2
```
成功编译效果图
<img width="648" height="458" alt="e69488f7a32c2016ddeb90640f3a8c53" src="https://github.com/user-attachments/assets/95fbb7e9-6fa1-4a26-81ee-94f7ae943e3f" />

### 3. 准备数据

确保`data/`目录中有测试数据文件：

```bash
# 检查数据文件
ls -la data/data14
```

### 4. 运行程序

```bash
# 运行主程序
./main_triple
运行结果图
<img width="598" height="633" alt="3fee399a3ca29e55b80d229ce8b28aa9" src="https://github.com/user-attachments/assets/110dd80a-e8bc-4c3e-ab8f-3ec33805764c" />


