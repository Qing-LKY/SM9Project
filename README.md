# SM9-Based Project demo

Fork from [WinterOrch/SM9Project](https://github.com/WinterOrch/SM9Project)

我们的终端主要提供了以下命令行功能:

-  ls  列出已注册的 UID
- reg 往系统中注册新的 UID
- su  切换当前用户到另一个 UID
- sig 以当前用户的 UID 对某个文件签名，生成我们设计的简易证书文件
- ver 通过证书中记录的 uid 对某个我们设计的证书文件进行验签
- enc 以某个用户的 UID 和公钥生成加密文件
- dec 以当前用户的 UID 对加密文件尝试解密

用于密码学基础实验大作业。
