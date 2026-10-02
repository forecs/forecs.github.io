# Windows防火墙到Azure防火墙与GSA的未来演进路线

## 结论先行

**Windows Firewall → Azure Firewall → Global Secure Access（GSA）, 安全执行点从“主机”扩展到“云网络”，再扩展到“身份感知的全球云边缘”。**

未来合理的目标架构不是关掉前一层，只保留后一层，而是形成三层协同：

1. **主机层：Windows Firewall**——每台终端/服务器最后一道东西向隔离与本机攻击面控制；
2. **工作负载网络层：Azure Firewall、Palo Alto Cloud NGFW**——保护 Azure VNet、Virtual WAN、混合网络的南北向和东西向流量；
3. **用户/分支访问层：Global Secure Access**——把互联网访问、SaaS、Microsoft 365 和私有应用访问迁移到身份感知的 SSE/ZTNA 控制面。

因此，“未来的防火墙”将从基于位置和 IP 的单点设备，演进为**分布式策略执行网格**：主机知道进程和设备状态，云防火墙知道工作负载和网络路径，GSA 知道用户身份、设备合规、风险与应用上下文。



## 一、三次边界迁移

### 1. Windows Firewall：边界下沉到每一台主机

Windows Firewall 是 Windows 内建、默认开启的主机型防火墙。它的核心价值不是替代网络防火墙，而是把最小权限落实到每个端点：

- 按应用、服务、程序、IP、端口、协议、接口和网络配置文件控制流量；
- 默认阻止未请求或无匹配规则的入站流量；
- 支持 Domain、Private、Public 三类网络配置文件；
- 与 IPsec 结合，可进行设备认证和加密；
- 即使外围设备、VPN 或云防火墙失效，仍保留本机隔离能力。

它代表传统边界安全向 **host micro-perimeter（主机微边界）** 的第一次迁移。

### 2. Azure Firewall / Cloud NGFW：边界上移到云工作负载网络

应用迁入 Azure 后，单台主机规则无法完成跨 VNet、跨订阅、混合网络和统一出入口治理。云防火墙把执行点放在 Hub VNet、Virtual WAN Hub 或工作负载流量路径中：

- 检查 VNet/Spoke 之间的东西向流量；
- 检查 Internet、on-premises 与 Azure 之间的南北向流量；
- 集中执行 SNAT/DNAT、FQDN/URL、威胁情报、IDPS、TLS Inspection；
- 通过 Firewall Policy、Panorama、Strata Cloud Manager 或 IaC 集中治理；
- 由云服务或厂商托管高可用、扩缩和生命周期。

它代表从主机微边界向 **cloud workload perimeter（云工作负载边界）** 的迁移。

### 3. Global Secure Access：边界移到身份感知的全球云边缘

用户、设备和应用不再稳定地位于企业局域网内，网络位置本身不再足以代表信任。GSA 通过 Microsoft Entra Internet Access 和 Microsoft Entra Private Access 把控制点迁移到 Microsoft SSE：

- Internet Access：身份感知的 Secure Web Gateway（SWG）；
- Private Access：按应用授权的 Zero Trust Network Access（ZTNA）；
- Conditional Access：把用户、设备合规、位置、风险等上下文加入网络策略；
- TLS Inspection、Web/FQDN Filtering、Threat Intelligence、DLP；
- 终端客户端或分支 Remote Network 将流量送入最近的云边缘。

它代表从网络位置边界向 **identity-aware edge（身份感知边缘）** 的迁移。

## 二、能力与责任边界对比

| 维度 | Windows Firewall | Azure Firewall Premium | Palo Alto Cloud NGFW for Azure | Palo Alto VM-Series | Global Secure Access |
| --- | --- | --- | --- | --- | --- |
| 主要保护对象 | 单台 Windows 终端/服务器 | Azure VNet、Hub-Spoke、vWAN 工作负载 | Azure VNet/vWAN 工作负载 | Azure 上的完整 PAN-OS 网络设备场景 | 用户、设备、分支到 Internet/SaaS/私有应用 |
| 执行位置 | 主机内核/网络栈 | Azure 区域网络服务 | Palo Alto 托管的 Azure 区域 SaaS | 客户自管 Azure VM/NVA | Microsoft 全球 SSE PoP |
| 主要上下文 | 应用、服务、端口、网络配置文件 | IP、端口、FQDN、URL、威胁情报 | App-ID、地址、服务、安全配置文件 | 完整 App-ID/User-ID/Zone/接口/路由语义 | 用户、设备、风险、Conditional Access、FQDN/URL |
| L3/L4 有状态过滤 | 是 | 是 | 是 | 是 | 部分；Cloud Firewall 当前为分支 Internet 五元组 |
| L7/TLS/威胁防护 | 有限；非其主职责 | Premium：TLS、IDPS、URL | IPS、URL、DNS Security、WildFire、TLS 等 | 最完整、可高度定制 | Internet Access：TLS、Web、Threat Intelligence、DLP |
| 东西向工作负载检查 | 单机入/出站 | 是 | 是 | 是 | 不是当前主定位 |
| 分支/漫游用户身份策略 | 很弱 | 弱，主要是网络对象 | 取决于管理方式，身份能力不等同 SSE | 可通过 User-ID/GlobalProtect 等实现 | 强，核心能力 |
| 私有应用按应用访问 | 本机规则 | 网络路径级 | 网络路径级 | 网络/应用级，仍偏 VPN/NGFW | Private Access/ZTNA 原生 |
| 路由、隧道、SD-WAN | 无 | 与 Azure 网络集成但非通用路由器 | 托管服务，传统设备网络功能有限 | 最完整：路由、IPsec/GRE、PBF、QoS、SD-WAN、GlobalProtect | Remote Network 用 IPsec/BGP 接入，但不是站点间传输网 |
| 运维责任 | 企业管理规则，Microsoft 管 OS 组件 | Microsoft 管服务；企业管策略 | Palo Alto 管基础设施/扩缩/升级；企业管策略 | 企业负责 VM、HA、扩缩、PAN-OS 生命周期与策略 | Microsoft 管 SSE；企业管身份、转发、安全配置文件 |

### 核心判断

- **Windows Firewall 不应被 GSA 或云防火墙淘汰**：GSA 看不到未被转发的本机横向流量；网络防火墙也不能替代进程级主机控制。
- **GSA 当前不能全面替代 Azure Firewall/NGFW**：Azure 工作负载的东西向检查、DNAT、复杂路由、完整 IDPS 与网络分段仍需工作负载网络防火墙。
- **Azure Firewall 与 GSA 存在功能重叠，但身份维度不同**：两者都有 Web/FQDN/TLS/威胁控制；GSA 强在用户和 Conditional Access，Azure Firewall 强在 VNet 数据平面与集中工作负载流量。
- **Palo Alto Cloud NGFW 与 VM-Series 的差异首先是运营模型，而非品牌或“安全强弱”**：Cloud NGFW 强在托管弹性；VM-Series 强在完整 PAN-OS 网络设备功能。


## 三、目标架构：三层策略执行网格

```text
用户/设备 ── GSA Client ─────────────┐
                                     ├─> Microsoft SSE Edge
分支网络 ── IPsec/BGP Remote Network ┘     ├─ Internet Access / SWG
                                           └─ Private Access / ZTNA

Azure/混合工作负载 ── vWAN / Hub VNet ──> Azure Firewall Premium

每一台 Windows 终端/服务器 ────────────> Windows Firewall
```

### 职责分工

#### Windows Firewall：始终保留

- 入站默认拒绝；
- 对管理端口、远程服务和服务器实施源地址限制；
- 与 Intune、Group Policy、Defender for Endpoint 等统一下发和监控；


#### Azure Firewall / Cloud NGFW：保护工作负载网络

- Azure VNet 与 on-premises 的东西向、南北向路径；
- 集中 egress、DNAT ingress、私有网络间分段；
- 工作负载级 TLS/IDPS、威胁情报和合规日志；


#### GSA：保护用户和分支的访问

- 漫游用户及分支访问 Internet、SaaS、Microsoft 365；
- 以用户/设备/风险为条件的 SWG 与 Conditional Access；
- 使用 Private Access 逐步替代面向用户的全隧道 VPN；
- 用 DLP、TLS Inspection、Threat Intelligence 保护用户数据路径；


## 四、安全演进

### 传统模型

```text
source subnet + destination IP + port = allow/deny
```

### 云工作负载模型

```text
workload/VNet + FQDN/URL + threat intelligence + TLS/IDPS = allow/deny/inspect
```

### 身份感知 SSE 模型

```text
user + device compliance + sign-in risk + application + content + session = allow/block/challenge/inspect
```

未来的防火墙演进重点不是寻找一个产品替换全部控制点，而是完成三项结构性变化：

1. **从“网络位置即信任”转向身份、设备、应用与会话共同决策；**
2. **从自管设备/虚拟机转向云原生、托管、弹性安全服务；**
3. **从单一边界转向主机、工作负载网络与全球 SSE 边缘协同。**

### Phase 0：建立事实基线（0–2 个月）

**目标：先看清流量和规则，再迁移产品。**

1. 盘点 Windows Firewall GPO/Intune 策略、例外、禁用设备和本机管理员覆盖；
2. 盘点 Azure VNet、vWAN、ExpressRoute/VPN、UDR、NVA、NAT、DNS 和流量路径；
3. 为流量分类：
   - 用户 → Internet/SaaS；
   - 用户 → 私有应用；
   - 工作负载 → Internet；
   - 工作负载 ↔ 工作负载；
   - on-premises ↔ Azure；
   - Internet → 发布服务；
4. 建立控制目标矩阵：身份、设备、应用、L3/L4、TLS、IDPS、DLP、日志、合规；
5. 统一日志到 Sentinel/Log Analytics 或现有 SIEM，先获取 30–60 天基线。

**完成标准：**每条关键流量有业务所有者、来源、目的、协议、所需身份上下文、所需检查级别和未来执行点。

### Phase 1：固化主机层和 Azure 工作负载层（2–6 个月）

**目标：建立不可被 SSE 取代的基础层。**

1. 恢复并强化 Windows Firewall 默认开启状态；
2. 把本机散落规则迁移到集中策略，删除无所有者和长期未命中的例外；
3. 为 Azure Landing Zone 建立标准 Hub-Spoke 或 vWAN 安全路径；
4. 对 Azure 工作负载选择主防火墙平台：
   - Azure 原生运维优先：Azure Firewall Premium；
   - Palo Alto 深度安全但希望托管：Cloud NGFW；
   - 完整 PAN-OS 网络能力不可缺：VM-Series；
5. 基于 Firewall Policy/Panorama/Strata 与 IaC 实现 policy-as-code；
6. 确保路由对称、DNS 设计正确、TLS 解密证书治理成熟。

**完成标准：**Windows 主机基线覆盖率可量化；Azure 关键流量经过一个明确且可观测的工作负载安全执行点。

### Phase 2：引入 GSA，先 Microsoft 流量和受控用户，再扩大到 Internet（4–12 个月）

**目标：从网络位置策略迁移到身份与设备上下文策略。**

建议顺序：

1. 小范围启用 Microsoft traffic profile，验证 Compliant Network、Source IP Restoration 和日志；
2. 对一组标准 Windows 终端试点 GSA Client；
3. 引入 Internet Access Web/FQDN Filtering，再评估 TLS Inspection、Threat Intelligence 与 DLP；
4. 把用户、设备合规、位置、登录风险纳入 Conditional Access；
5. 对分支使用 Remote Network 接入，先观察后执行；
6. 解决 QUIC、Secure DNS、代理、NRPT、VDI/多会话和业务地理定位依赖；
7. 明确与 Defender for Endpoint Web Content Filtering、Azure Firewall Web Categories 的策略归属，避免三处重复维护。

**完成标准：**用户 Internet/SaaS 流量可按身份和设备策略控制；旁路、故障回退和紧急放行流程经过演练。

### Phase 3：用 Private Access 分批替代用户 VPN（9–18 个月）

**目标：从“连上网络”转为“只访问获准应用”。**

1. 发现现有 VPN 后的真实应用依赖；
2. 优先迁移 Web、RDP、SSH、数据库等边界清晰的应用；
3. 按 FQDN/IP、端口和应用建立 Private Access segment；
4. 使用 Conditional Access 做按用户、组、设备合规和风险的授权；
5. 对无法迁移的广播、复杂 UDP、设备管理或非标准协议保留受限 VPN；
6. 逐步缩小 VPN 可达网段，最终关闭不必要的全网访问。

**完成标准：**大多数用户不再获得网络级广泛访问；私有应用访问具有应用级授权、审计和持续评估。

### Phase 4：评估 GSA Cloud Firewall，但仅在能力匹配时承接分支 L3/L4（持续观察）

**当前适合的范围：**

- 分支 Remote Network 的 Internet egress；
- 简单 IPv4 五元组 Allow/Block；
- 与 GSA Security Profile 的基础统一管理。

**当前不应迁移的范围：**

- GSA Client 流量的 Cloud Firewall 五元组控制（当前不支持）；
- 目的 FQDN Cloud Firewall 规则（当前不支持；应区分于 Internet Access 的 Web/FQDN Filtering）；
- Default Deny 分支防火墙设计（当前默认动作固定 Allow）；
- Azure VNet 东西向、DNAT、复杂路由、完整 NGFW/IDPS 需求；
- 需要即时策略生效的场景（当前文档说明约需 15–20 分钟）。

**升级门槛：**只有当 Microsoft 文档明确支持所需流量来源、Default Deny、FQDN/应用规则、所需协议、日志/SIEM、HA/SLA 和变更时延后，才把相应控制从传统防火墙迁移到 GSA Cloud Firewall。



## 参考资料

1. Microsoft Learn — [Windows Firewall Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
2. Microsoft Learn — [What is Azure Firewall?](https://learn.microsoft.com/en-us/azure/firewall/overview)
3. Microsoft Learn — [Azure Firewall features by SKU](https://learn.microsoft.com/en-us/azure/firewall/features-by-sku)
4. Microsoft Learn — [Install Palo Alto Networks Cloud NGFW in a Virtual WAN hub](https://learn.microsoft.com/en-us/azure/virtual-wan/how-to-palo-alto-cloud-ngfw)
5. Palo Alto Networks — [Cloud NGFW for Azure vs VM-Series Firewall Feature Comparison](https://live.paloaltonetworks.com/t5/cloud-ngfw-for-azure-articles/cloud-ngfw-for-azure-vs-vm-series-firewall-feature-comparison/ta-p/588332)
6. Palo Alto Networks — [Cloud NGFW for Azure Security Services](https://docs.paloaltonetworks.com/cloud-ngfw/azure/cloud-ngfw-for-azure/native-policy-management/cloud-ngfw-for-azure-security-services)
7. Microsoft Learn — [What is Global Secure Access?](https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access)
8. Microsoft Learn — [Learn about Microsoft Entra Internet Access](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-internet-access)
9. Microsoft Learn — [Configure Global Secure Access cloud firewall](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-cloud-firewall)
10. Microsoft Learn — [Known Limitations for Global Secure Access](https://learn.microsoft.com/en-us/entra/global-secure-access/reference-current-known-limitations)
11. Microsoft Learn — [Global Secure Access remote network connectivity](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-remote-network-connectivity)
