# ipsec_diag — strongSwan/IPSec 站点间隧道排障工具

面向分支机构 site-to-site 隧道"隔三差五断、对着 charon 日志干瞪眼"的场景。
读两端的 **swanctl.conf / ipsec.conf** 做静态比对，再解析两端 **charon 日志**、
按修正后的时间轴对齐还原完整协商过程，定位卡点、给出可直接照抄的改法，输出**单文件 HTML**。

零第三方依赖，标准库实现，Python 3.10+（开发环境 3.15 验证）。

## 能力清单

### 静态配置比对（双格式自动识别）
- IKE 提议：加密 / PRF / 完整性 / DH 组，算法别名归一（`aes256`==`AES_256`==`aes-256`，
  `modp2048`==`dh14`，AEAD 内置完整性等），算多提议交集
- ESP 提议与 PFS 组（含一端 PFS、一端 none 的情形）
- 流量选择器子网：本端 local_ts ↔ 对端 remote_ts 双向做网络包含/重叠校验，裸 IP 自动补 /32
- 认证方式：psk / pubkey / EAP / xauth，含 authby 老式推断
- 对端 ID：类型前缀（fqdn/ipv4/keyid…）+ 值双重比对
- IKE / ESP 生存期：未配置按 strongSwan 常见默认值（3h / 1h），差异 ≥2 倍给风险提示
- DPD delay/timeout、开关不一致、reauth/rekey 策略、IKE 版本

### 双端 charon 日志重建
- 支持 syslog（`Nov 8 10:23:14 gw charon[123]:`，无年份用 `--log-year` 补）、
  ISO 带毫秒、纯时间三种格式
- 按 IKE_SA 归并生命周期，识别 IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA / INFORMATIONAL
- **时钟偏移自动估计**：用两端收发配对取中位差，修正后再对齐显示（样例 S7 演示 1.2s 偏差）
- 标准 7 步协商流程还原，标出停滞步骤
- 识别：NO_PROPOSAL_CHOSEN（区分 IKE 阶段还是 CHILD 阶段）、INVALID_KE_PAYLOAD、
  AUTHENTICATION_FAILED、PSK 不一致、ID 校验失败、证书链失败、TS_UNACCEPTABLE、
  DPD 宣告死亡、重传耗尽、NAT 映射老化、**rekey/reauth 碰撞（RFC 7296）**
- 静态问题与日志证据按主题合并，两边都出现时标注"日志已证实"

## 用法

```bash
# 方式一：显式给四个文件（任意子集也行，缺配置或缺日志自动降级）
python3 -I ipsec-diag.py \
  --local-conf  /path/hq/swanctl.conf   --remote-conf /path/branch/ipsec.conf \
  --local-log   /path/hq/charon.log     --remote-log  /path/branch/charon.log \
  -o report.html --log-year 2026

# 方式二：给两端目录，自动发现 swanctl.conf|ipsec.conf 和 *.log|syslog
python3 -I ipsec-diag.py --local-dir hq/ --remote-dir branch/ -o report.html

# 生成 7 组典型故障样例（配置+双端日志，混合两种配置格式）
python3 -I ipsec-diag.py --gen-samples ./samples

# 对 7 组样例逐组出报告并生成索引页（输出到 ./demo_reports/）
python3 -I ipsec-diag.py --demo ./samples --log-year 2026

# 内置 35 项自检
python3 -I ipsec-diag.py --selftest
```

> `-I`（隔离模式）禁止从当前目录隐式 import，防止日志/配置目录里被植入 `json.py` 之类的模块。
> 工具本身只读文本、不执行配置内容。

## 7 组样例覆盖的典型故障

| 编号 | 故障 | 日志特征 / 卡点 |
|---|---|---|
| s1 | IKE 提议无交集 | SA_INIT 即回 NO_PROPOSAL_CHOSEN，停在第 1~2 步 |
| s2 | ESP/PFS 不匹配 | IKE 建链成功，CREATE_CHILD_SA 被拒，隧道起不来 |
| s3 | PSK 不一致 | IKE_AUTH 回 AUTHENTICATION_FAILED，重传耗尽 |
| s4 | 子网不匹配 | TS_UNACCEPTABLE，IKE 活着但 CHILD_SA 建不起来 |
| s5 | 对端 ID 不符 | constraint check failed，本端主动回 AUTH_FAILED |
| s6 | NAT 老化 + DPD 误判 | DPD 重传 3 次宣告对端死亡，DELETE 拆 SA |
| s7 | rekey 碰撞 + 生存期悬殊 | 两端同发 CREATE_CHILD_SA，含 1.2s 时钟偏移修正 |

## 目录结构

```
ipsec_diag/
  model.py          数据模型
  config_parser.py  swanctl 花括号语法 + ipsec.conf 段语法解析、算法/子网/ID 归一
  static_check.py   逐项静态比对与静态结论
  log_parser.py     charon 日志解析、时钟偏移估计、SA 生命周期归并
  diagnose.py       协商时间轴、卡点定位、rekey 碰撞识别、动静证据合并
  html_report.py    单文件 HTML（内嵌 CSS/JS，无外部依赖）
  samples.py        7 组自洽样例生成器
  selftest.py       内置自检
  main.py           CLI 入口
ipsec-diag.py       薄启动器
```

## 设计取舍（按最常见部署形态处理的默认值）

- 场景默认 IKEv2 site-to-site、tunnel 模式；每端单连接时同名优先否则取第一条配对
- 未显式配置的生存期/DPD 按 strongSwan 5.x 常见值（IKE 3h、ESP 1h、DPD 30/150s）参与比对并标注"(默认)"
- 未配置提议时按内置默认提议集展开，报告中说明是兜底而非用户显式配置
- 解析失败不致命：错误展示在报告"输入与解析"一节，其余分析继续
