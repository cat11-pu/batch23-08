# GSB Bugfix Task
## 题面
多租户临时文件读写并发场景下出现数据污染：文件写入无原子操作、缺少文件锁、存在TOCTOU竞态、未检查文件所有者、临时文件可被其他用户篡改；storage/tmp_file.py 是核心，tests/test_tmp_concurrency.py 15个红。要修的是：使用原子写入、增加排他文件锁、消除TOCTOU时间窗口、校验文件属主、临时文件随机命名。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
