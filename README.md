# VLSE 
### 依赖库
- **CMake** >= 3.10
- **C++14** 编译器支持
- **OpenSSL** 库
- **Crypto++** 库  
- **NTL** (Number Theory Library) 库
- **Xcode** 15.3
### 安装依赖 (macOS)

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


