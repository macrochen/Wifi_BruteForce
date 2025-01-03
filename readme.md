这是一个用于测试WiFi网络安全性的工具。它可以扫描周围的WiFi网络，并尝试使用密码字典进行密码破解。

## ⚠️ 免责声明

本工具仅用于教育目的和网络安全测试。未经授权对WiFi网络进行破解可能违反法律。使用本工具时请确保：
1. 只对自己拥有的网络进行测试
2. 已获得网络所有者的明确授权
3. 不用于任何非法用途

## 🔧 系统要求

- Python 3.6+
- macOS 系统（当前版本专门针对macOS优化）
- root权限（需要控制网络接口）
- 网络接口支持监听模式

## 📦 安装

1. 克隆仓库：
```bash
git clone https://github.com/yourusername/wifi-bruteforce.git
cd wifi-bruteforce
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 🚀 使用方法

### 基本命令

1. 列出可用的WiFi网络：
```bash
sudo python wifi_bruteforce.py -l
```

2. 更新密码字典：
```bash
sudo python wifi_bruteforce.py -u
```

3. 破解指定的WiFi网络：
```bash
sudo python wifi_bruteforce.py -s "WiFi名称"
```

4. 使用自定义密码文件：
```bash
 sudo python wifi_bruteforce.py -s "WiFi名称" -p /path/to/your/passwords.txt
```

5. 优化密码字典：
```bash
python password_optimizer.py wordlists/passwords.txt -o wordlists/optimized_passwords.txt
```

5. 交互式选择并破解：
bash
sudo python wifi_bruteforce.py


### 命令行参数

- `-h, --help`: 显示帮助信息
- `-i INTERFACE, --interface INTERFACE`: 指定网络接口（默认：en0）
- `-u, --update`: 更新密码字典
- `-s SSID, --ssid SSID`: 指定要破解的WiFi名称
- `-l, --list`: 列出可用的WiFi网络
- `-p FILE, --password-file FILE`: 指定自定义的密码字典文件

## 🛠 工作原理

1. **网络扫描**
   - 使用 system_profiler 获取周围WiFi网络信息
   - 显示每个网络的SSID、信号强度、信道和加密类型
   - 自动排除当前连接的网络
   - 按信号强度排序

2. **密码字典**
   - 默认使用在线密码字典（来自SecLists项目）
   - 支持本地缓存，避免重复下载
   - 可以随时更新密码库

3. **破解过程**
   - 对选定的网络逐个尝试密码字典中的密码
   - 使用系统网络命令尝试连接
   - 通过多重验证确保连接成功
   - 显示详细的破解进度

4. **安全特性**
   - 连接失败时自动断开
   - 支持中断操作
   - 详细的错误报告
   - 避免重复尝试

5. **密码优化**
   - 自动过滤无效的WiFi密码
   - 去除重复密码
   - 按长度排序（优先尝试短密码）
   - 验证密码格式（长度、字符集等）
   - 生成优化后的密码字典

6. **断点续传**
   - 自动保存破解进度
   - 支持中断后继续破解
   - 记录已尝试的密码数量
   - 智能恢复上次位置

## 📝 注意事项

1. **性能考虑**
   - 破解速度受网络响应时间影响
   - 密码字典越大，耗时越长
   - 建议先使用小型字典测试
   - 优化了连接验证流程，减少等待时间
   - 使用快速失败机制，提高尝试速度
   - 支持断点续传，可随时中断恢复
   - 建议根据网络条件调整连接超时时间

2. **兼容性**
   - 当前版本主要支持macOS系统
   - 需要root权限
   - 支持WPA/WPA2加密的网络

3. **故障排除**
   - 确保网络接口名称正确（通常是en0）
   - 检查是否有足够的权限
   - 确保目标网络在范围内
   - 如果连接hang住，可以按Ctrl+C中断

## 🔄 更新日志

- v1.0.0
  - 初始版本发布
  - 支持macOS系统
  - 基本的WiFi扫描和破解功能
  - 密码字典管理

## 📄 许可证

MIT License

## 👥 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 🔗 相关项目

- [SecLists](https://github.com/danielmiessler/SecLists) - 密码字典来源
- [Python-Wifi](https://github.com/python-wifi/python-wifi) - WiFi操作库' > readme.md