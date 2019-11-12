# 使用gdb调试glibc
1. 查看glibc版本号
```
ldd <prog>
```
2. 根据glibc的版本安装符号表
 ```
sudo apt-get install libc6-dbg
```
3. 安装glibc的源文件
```
sudo apt-get source libc-dev
```

