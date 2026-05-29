# 藍隊 CTF — Claude Code Skills 與 Agents

> **語言:** [English](README.md) · **繁體中文**

一套完整的 Claude Code skill + subagent 套件，專為防禦型資安學習與競賽設計：**AIS3 MyFirstCTF**、**金盾獎**、**HITCON Cyber Range**、**CyberDefenders**、**LetsDefend**、**BTLO**、**HTB Sherlocks**，以及真實 SOC tier-1 / IR 工作。

基於《藍隊 CTF 完整指南：整合版》打造。

---

## 內容總覽

```
blueteam-ctf-project/
├── PRD.md                  產品需求文件
├── SPEC.md                 技術規格書
├── claude-plugin.json      Plugin 安裝資訊
│
├── skills/                 7 個 skill（SKILL.md + 範本）
│   ├── blueteam-triage/    入口路由器
│   ├── pcap-analysis/      網路鑑識四階段 SOP
│   ├── memory-forensics/   Volatility 3 調查腳本
│   ├── log-hunter/         Windows EVTX / Linux / SIEM 獵捕
│   ├── ioc-extractor/      regex IOC 擷取 + 還原 + 遮罩
│   ├── detection-engineer/ Sigma / YARA / Suricata 規則撰寫
│   └── ir-report/          BTL1 對齊的六段式報告產生器
│
├── agents/                 5 個 subagent
│   ├── soc-analyst.md         tier-1 告警分流
│   ├── dfir-investigator.md   深度 memory / disk / PCAP 調查
│   ├── threat-hunter.md       假設驅動的威脅獵捕
│   ├── detection-engineer.md  規則生命週期擁有者
│   └── ir-reporter.md         最終報告編譯與審查
│
├── scripts/                Python 3.10+（stdlib，選用 scapy/yaml）
│   ├── extract_iocs.py     IOC 擷取 + 還原 + --redact 隱私模式
│   ├── pcap_preflight.py   PCAP 宏觀概覽
│   └── validate_sigma.py   Sigma 2.0 schema 驗證
│
├── templates/              IR 報告、Sigma、YARA、5W 筆記
├── examples/               IOC 範例文字 + CTF 完整 walkthrough
└── docs/                   安裝、隱私
```

## 快速開始

### 1. 安裝為 Claude Code plugin（推薦）

```bash
cp -R blueteam-ctf-project ~/.claude/plugins/blueteam-ctf
```

或從任意位置 clone：

```bash
git clone <repo> ~/blueteam-ctf-project
cd ~/blueteam-ctf-project
```

Skills 自動由 `skills/` 註冊；agents 由 `agents/` 註冊。若 Claude Code 已開啟請重啟。

### 2. 煙霧測試

```bash
python3 scripts/extract_iocs.py examples/sample-iocs.txt
python3 scripts/pcap_preflight.py --help
python3 scripts/validate_sigma.py templates/sigma-template.yml
```

### 3. 試跑一個工作流

在 Claude Code 中：

```
/blueteam-triage 我剛下載了 CyberDefenders 的 WebStrike.pcap
```

triage skill 會分類 artefact、建立 `findings.md`、並路由到 `/pcap-analysis`。

## 典型工作流

### A. 個人 CTF 解題（CyberDefenders easy）

1. `/blueteam-triage <artefact>` — 分類並建立筆記
2. `/pcap-analysis` 或 `/memory-forensics` 或 `/log-hunter` — 深度調查
3. `/ioc-extractor` — 彙整 IOC
4. `/detection-engineer` — 撰寫 Sigma 規則（履歷加分項）
5. `/ir-report` — 產出 writeup。發布到 Medium / GitHub Pages

### B. 真實 SOC 模擬（LetsDefend / OpenSOC）

1. `@soc-analyst` — 貼上告警，取得 TP/FP 判決與 3 條 pivot query
2. 升級 → `@dfir-investigator` — 跨 memory + disk + log 關聯分析
3. `@threat-hunter` — 獵捕橫向擴散
4. `@detection-engineer` — 為每個防禦缺口撰寫規則
5. `@ir-reporter` — 完成六段式報告

### C. 團隊賽事（HITCON Cyber Range）

多個 agent 平行對應不同 artefact，合併 `findings.md`，最後由 `@ir-reporter` 完稿。

## 隱私保護

本專案預設你會處理機敏資料，**預設行為偏向資料本地化**。

- 每個 skill 開頭都有隱私提醒
- `scripts/extract_iocs.py --redact` 可在本機替換 email / IP，產出本地遮罩對應表
- 若需最高隱私，建議跑本地 LLM（Ollama + Foundation-Sec-8B 或 WhiteRabbitNeo-V3）— 詳見 `docs/privacy.md`

## 版本規劃

- v1.0（本次釋出）：所有 skills、agents、scripts、templates、docs
- v1.1：中文 SKILL.md 鏡像、MCP server 範例（Splunk / CrowdStrike）
- v1.2：Security Onion + Wazuh 的 Docker compose

完整 roadmap 見 `PRD.md` §11。

## 相依套件

- **必要：** Python 3.10+、Claude Code
- **選用：** PyYAML（`validate_sigma.py` 需要）、scapy（`pcap_preflight.py` 完整功能）

```bash
pip install pyyaml scapy
```

## 七個 Skill 速查

| Skill | 觸發時機 | 主要產出 |
|-------|---------|---------|
| `blueteam-triage` | 任何防禦型 artefact 入手；不知從何下手 | 5W 筆記骨架 + 路由建議 |
| `pcap-analysis` | `.pcap` / `.pcapng` 在手 | 四階段 SOP 結果 + IOC + Suricata 草稿 |
| `memory-forensics` | `.dmp` / `.mem` / `.raw` | Volatility 3 流程結果 + process anomaly + 持久化指標 |
| `log-hunter` | EVTX / auth.log / IIS / SIEM 匯出 | SPL/KQL 查詢 + 對應 ATT&CK |
| `ioc-extractor` | 混雜文字、TI 報告、log 片段 | 去重後 IOC 表 |
| `detection-engineer` | 想把 TTP 轉成規則 | Sigma/YARA/Suricata 規則 + ART 測試對應 |
| `ir-report` | 調查完成或暫停寫報告 | 六段式 IR 報告 |

## 五個 Agent 速查

| Agent | Model | 用途 |
|-------|-------|------|
| `@soc-analyst` | sonnet | Tier-1 告警分流，TP/FP 判決 + 3 條 pivot |
| `@dfir-investigator` | opus | 深度跨來源關聯，維持監管鏈 |
| `@threat-hunter` | opus | 假設驅動獵捕，ART 驗證迴圈 |
| `@detection-engineer` | sonnet | 規則生命週期、UUID + CHANGELOG |
| `@ir-reporter` | opus | 最終報告 + 同儕審查清單 |

## 對應台灣藍隊賽事

| 賽事 | 推薦使用 |
|------|---------|
| **AIS3 MyFirstCTF**（每年 4-5 月，免費 80 名） | `/blueteam-triage` + `/pcap-analysis` + `/log-hunter` 三件套 |
| **金盾獎**（每年 9-1 月） | 五個 skill 全用，特別是 `/memory-forensics` |
| **HITCON Cyber Range**（7-10 月） | 全 agent 平行作戰 |
| **HITCON Defense**（CDX 模式） | `@threat-hunter` + `@detection-engineer` 為主，搭配情資共享 |
| **金融 F-ISAC 演練** | `@ir-reporter` 產出符合金管會要求的報告格式 |

## 貢獻

請參考 `SPEC.md` 中 skill / agent / script 撰寫規範。歡迎 PR。

## 授權

MIT。詳見 `LICENSE`。

## 致謝

基於《藍隊 CTF 完整指南：整合版》整合多份深度研究。引用來源包括：
TryHackMe SOC L1 / SAL1、LetsDefend、CyberDefenders、BTLO、HTB Sherlocks、
Security Blue Team BTL1、SANS DFIR、MITRE ATT&CK、SigmaHQ、SwiftOnSecurity、
The DFIR Report、13Cubed、John Hammond、AIS3、HITCON。
