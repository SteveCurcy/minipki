# MiniPKI
[![](https://img.shields.io/badge/Author-Xu.Cao-lightgreen)](https://github.com/SteveCurcy) ![](https://img.shields.io/badge/Version-0.0.1-yellow)

🎯 本项目的目标是实现一个小型的 PKI 系统模拟器。主要使用的技术是 Linux 系统提供的 Network Namespace 隔离机制。

## 安装依赖

本项目需要创建和管理 Linux Network Namespace，因此需要借助 pyroute2 库。因此，在尝试运行项目前，请先安装依赖库：

```shell
pip install pyroute2
```