# zuc序列密码算法 C源码

密钥生成算法位于ZUC_main.h文件中

EE3A为机密性算法

EI3A为完整性算法



update：重构了代码，重新编辑了头文件，使得主算法在加密与完整性算法中可以被顺利调用
update2：引入了测试数据，分别验证密钥流生成、加密算法、完整性算法与官方文档的一致性！

This is a demo without main（）

update4：新增SM4密码算法！



