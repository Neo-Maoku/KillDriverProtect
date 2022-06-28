# KillDriverProtect
1. **关闭恶意驱动的文件和注册表保护**
   - 去除MINIFilter的IRP_MJ_CREATE的PRE回调,IRP_MJ_DIRECTORY_CONTROL的PRE和POST回调
   - 使用CmUnRegisterCallback去除注册表回调
2. **当前只在win7(x86，x64)，win10（x64）系统上测试过，且均测试成功**
3. **使用方法**
   - 拷贝KillDriverProtect.inf和KillDriverProtect.sys到目标机器
   - 使用禁用签名方式启动机器
   - 右击KillDriverProtect.inf，点安装
   - 已管理员权限启动cmd
   - 启动服务：**sc start KillDriverProtect**
