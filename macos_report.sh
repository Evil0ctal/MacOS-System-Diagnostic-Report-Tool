#!/bin/bash
# MacBook验机脚本 V1.0.0 - by Evil0ctal
# 功能：全面检查企业锁、系统完整性、硬件信息、电池健康、网络身份等关键字段
# 输出：纯终端、中文结构、带颜色、带风险标记

# ---------------------- 样式定义 ------------------------
RED='\033[0;31m'       # 红色 - 严重
GREEN='\033[0;32m'     # 绿色 - 正常
YELLOW='\033[1;33m'    # 黄色 - 警告
NC='\033[0m'           # 无色

print_title() {
  echo -e "\n${YELLOW}🧠 $1${NC}"
  echo "-------------------------------------------------------------"
}

section() {
  echo -e "\n${GREEN}>> $1${NC}"
}

risk() {
  echo -e "${RED}❗ $1${NC}"
}

warn() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

ok() {
  echo -e "${GREEN}✅ $1${NC}"
}

header() {
  echo -e "\n${YELLOW}================= 🍎 MacOS 验机报告 =================${NC}"
  echo "日期: $(date)"
  echo "执行用户: $(whoami)"
  echo "主机名称: $(scutil --get ComputerName)"
  echo "操作系统: $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "-------------------------------------------------------------"
}

# ---------------------- 执行开始 ------------------------
clear
header

# 模块 1️⃣：设备身份与硬件合法性
section "1. 设备基本身份与合法性"

MODEL=$(system_profiler SPHardwareDataType | grep "Model Identifier" | awk -F: '{print $2}' | xargs)
CHIP=$(system_profiler SPHardwareDataType | grep "Chip" | awk -F: '{print $2}' | xargs)
SERIAL=$(system_profiler SPHardwareDataType | grep "Serial Number (system)" | awk -F: '{print $2}' | xargs)
UUID=$(system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F: '{print $2}' | xargs)
MLB=$(ioreg -l | grep "board-id" | awk -F '"' '{print $4}')

echo "  📌 型号:        $MODEL"
echo "  📌 芯片:        $CHIP"
echo "  📌 序列号:      $SERIAL"
echo "  📌 主板ID(MLB): $MLB"
echo "  📌 UUID:        $UUID"

# 国家/地区判断（用序列号前4位）
SERIAL_PREFIX=$(echo $SERIAL | cut -c9-10)
case $SERIAL_PREFIX in
  F0|FV|G0) REGION="美国";;
  C0|CK|DL) REGION="中国";;
  DK|DM|DN) REGION="爱尔兰";;
  DQ|DT|DY) REGION="新加坡";;
  *) REGION="未知";;
esac
echo "  🌐 出厂区域:    $REGION（前缀: $SERIAL_PREFIX）"

# 判断是否串号不符（仅逻辑提示）
[[ "$MLB" == "" ]] && risk "无法提取主板ID，可能为改机或非法刷写" || ok "主板 ID 提取成功"

# 模块 2️⃣：企业控制、MDM、配置锁分析
section "2. 企业控制检查（DEP / MDM / 配置锁）"

# profiles 状态
DEP=$(profiles status -type enrollment | grep "Enrolled via DEP" | awk -F: '{print $2}' | xargs)
MDM=$(profiles status -type enrollment | grep "MDM enrollment" | awk -F: '{print $2}' | xargs)

echo "  📎 DEP 注册状态: $DEP"
echo "  📎 MDM 管理状态: $MDM"

[[ "$DEP" == "Yes" ]] && warn "设备已注册 DEP，可能属于企业批量注册设备"
[[ "$MDM" == "Yes" ]] && risk "设备当前受 MDM 管理，具有远程配置锁风险"
[[ "$DEP" != "Yes" && "$MDM" != "Yes" ]] && ok "未发现企业控制注册记录"

# Configuration Lock 检查
CFGURL=$(ioreg -l | grep -i ConfigurationURL)
if [[ -n "$CFGURL" ]]; then
  risk "检测到配置锁 URL，存在企业锁"
  echo "     $CFGURL"
else
  ok "未发现配置锁 URL"
fi

# MDM 配置文件分析
echo "  📎 当前配置文件包含:"
profiles list | grep -E 'attribute|ProfileIdentifier|PayloadType' | sed 's/^/     📄 /'

# 检查 MDM Payload 中是否有 DeviceManagement
MDM_PAYLOAD=$(profiles show | grep -i "com.apple.mdm")
if [[ -n "$MDM_PAYLOAD" ]]; then
  risk "发现 MDM Payload 配置，可能存在配置锁或被控行为"
else
  ok "未发现 MDM Payload 配置"
fi

# Setup Assistant 是否跳过
echo ""
echo "  🛠 激活流程状态:"
if [ -f /var/db/.AppleSetupDone ]; then
  warn "系统检测到激活流程已完成标志（.AppleSetupDone 存在）"
else
  ok "未跳过 Setup Assistant，激活流程完整"
fi

# 可疑脚本注入检查
echo ""
echo "  🔍 检查 LaunchDaemons 中可疑启动项:"
DAEMONS=$(ls /Library/LaunchDaemons 2>/dev/null | grep -iE 'bypass|mdm|config|disable|activation|unlock')
if [[ -n "$DAEMONS" ]]; then
  risk "检测到可疑启动项："
  echo "$DAEMONS" | sed 's/^/     🔥 /'
else
  ok "未发现异常启动项"
fi

# 查看 RemoteManagement 服务状态
echo ""
echo "  🖥️ 远程管理（RemoteManagement）状态:"
pgrep ARDAgent >/dev/null && warn "远程桌面 ARDAgent 正在运行（可能被远程控制）" || ok "未发现远程管理行为"

# 模块 3️⃣：系统完整性与安全性分析
section "3. 系统安全机制状态（SIP / FileVault / Secure Boot / 降级检测）"

# SIP 状态（System Integrity Protection）
SIP_STATUS=$(csrutil status 2>/dev/null)
if [[ "$SIP_STATUS" == *"enabled"* ]]; then
  ok "SIP（系统完整性保护）已开启"
else
  risk "SIP 已被关闭，系统完整性已失效！可能存在风险操作"
fi
echo "     🔐 $SIP_STATUS"

# Gatekeeper 状态（下载程序验证）
GK_STATUS=$(spctl --status 2>/dev/null)
if [[ "$GK_STATUS" == *"enabled"* ]]; then
  ok "Gatekeeper 启用，系统验证机制正常"
else
  warn "Gatekeeper 被关闭，可执行程序验证被绕过"
fi
echo "     🛡️ $GK_STATUS"

# FileVault 状态（磁盘加密）
FV_STATUS=$(fdesetup status 2>/dev/null)
if [[ "$FV_STATUS" == *"On"* ]]; then
  ok "FileVault 已开启，磁盘加密安全"
else
  warn "FileVault 未启用，磁盘未加密"
fi
echo "     💾 $FV_STATUS"

# 安全启动模式（仅 T2 / Apple Silicon 有效）
SB_MODE=$(nvram -p 2>/dev/null | grep -i SecureBootModel)
if [[ -n "$SB_MODE" ]]; then
  echo "     🔐 安全启动参数: $SB_MODE"
  ok "检测到安全启动配置参数"
else
  warn "未检测到 SecureBootModel，可能为旧机型或未设置"
fi

# T2 芯片存在性判断
T2_CHIP=$(system_profiler SPiBridgeDataType | grep -i "T2 Security Chip")
if [[ -n "$T2_CHIP" ]]; then
  ok "已检测到 T2 安全芯片"
else
  echo "     🧬 无 T2 芯片信息，或为 Apple Silicon 架构"
fi

# 越狱 / 降级风险路径检测
echo ""
echo "  🧪 系统降级 / 破解风险路径:"
if [ -d "/System/Library/Sandbox/Profiles" ]; then
  ok "未检测到降级文件缺失"
else
  risk "Sandbox Profiles 缺失或异常，系统完整性可能被篡改"
fi

if [ -f "/usr/lib/libhook.dylib" ] || [ -f "/usr/lib/substrate.dylib" ]; then
  risk "检测到 Hook 插件残留，可能存在越狱行为"
else
  ok "无明显越狱痕迹"
fi

# 模块 4️⃣：电池健康状态检查
section "4. 电池健康状态分析"

CYCLE_COUNT=$(system_profiler SPPowerDataType | awk '/Cycle Count/{print $3}')
BAT_HEALTH=$(system_profiler SPPowerDataType | grep "Condition" | awk -F: '{print $2}' | xargs)
CURRENT_CAPACITY=$(system_profiler SPPowerDataType | awk '/Full Charge Capacity/{print $4}')
DESIGN_CAPACITY=$(system_profiler SPPowerDataType | awk '/Design Capacity/{print $4}')

echo "  🔋 循环次数: $CYCLE_COUNT 次"
echo "  🔋 当前容量: $CURRENT_CAPACITY mAh"
echo "  🔋 设计容量: $DESIGN_CAPACITY mAh"
echo "  🔋 健康状态: $BAT_HEALTH"

[[ "$CYCLE_COUNT" -gt 1000 ]] && warn "电池循环次数过高，需留意老化" || ok "电池循环次数在安全范围内"
[[ "$BAT_HEALTH" != "Normal" && "$BAT_HEALTH" != "Good" ]] && risk "电池状态异常，建议更换" || ok "电池状态良好"

# 模块 5️⃣：磁盘/SSD健康信息
section "5. 存储设备信息 & SMART 检查"

DISK_ID=$(diskutil list | grep "Apple_APFS Container" | awk '{print $NF}' | head -n1)
DISK_INFO=$(diskutil info "$DISK_ID" 2>/dev/null)

echo "  💽 设备标识符: $DISK_ID"
echo "$DISK_INFO" | grep -E "Device Node|Disk Size|Media Name|Medium Type|Solid State|File System Personality" | sed 's/^/     🧷 /'

# SMART 状态（非 Apple Silicon）
SMART=$(diskutil info "$DISK_ID" | grep "SMART Status" | awk -F: '{print $2}' | xargs)
[[ "$SMART" == "Verified" ]] && ok "SMART 状态正常" || risk "SMART 状态异常，请谨慎使用"

# TRIM 支持
TRIM=$(system_profiler SPSerialATADataType 2>/dev/null | grep "TRIM" | awk -F: '{print $2}' | xargs)
[[ "$TRIM" == "Yes" ]] && ok "SSD 支持 TRIM（对性能/寿命有利）" || warn "未启用 TRIM，可能为第三方 SSD"

# 模块 6️⃣：挂载点分析（是否存在非法分区）
section "6. APFS 分区 & 挂载结构分析"

echo "  📂 当前挂载点:"
mount | grep "^/dev/" | awk '{print $1, "->", $3}' | sed 's/^/     📌 /'

# 检查是否有异常 APFS snapshots
SNAPSHOTS=$(tmutil listlocalsnapshots / 2>/dev/null | wc -l)
if [[ "$SNAPSHOTS" -gt 10 ]]; then
  warn "检测到大量 APFS 快照，可能导致系统回滚风险"
else
  ok "APFS 快照数量正常（$SNAPSHOTS 个）"
fi

# 模块 7️⃣：系统环境与用户活动分析
section "7. 系统环境与用户行为"

echo "  🖥️ 操作系统版本: $(sw_vers -productVersion)"
echo "  🧠 内核版本: $(uname -a)"
echo "  👤 当前用户: $(whoami)"
echo "  🕒 系统已运行时间: $(uptime | awk -F "," '{print $1}' | sed 's/^/     ⏱ /')"

# 登录历史（可能用于判断是否为企业用户或多人共享）
echo ""
echo "  📜 最近 5 条登录历史："
last -5 | sed 's/^/     🧑‍💻 /'

# 当前默认 shell（判断是否被修改）
DEF_SHELL=$(dscl . -read /Users/$(whoami) UserShell | awk '{print $2}')
echo "  🧾 默认 Shell: $DEF_SHELL"
[[ "$DEF_SHELL" == "/bin/zsh" || "$DEF_SHELL" == "/bin/bash" ]] && ok "默认 shell 正常" || warn "默认 shell 异常或被修改"

# /etc/sudoers 检查（防止后门提权）
echo ""
echo "  🔐 检查 sudoers 文件是否被修改:"
SUDOERS_HASH=$(shasum -a 256 /etc/sudoers | awk '{print $1}')
[[ "$SUDOERS_HASH" != "" ]] && ok "sudoers 文件 hash: $SUDOERS_HASH" || risk "无法读取 sudoers，或已被破坏"

# 模块 8️⃣：网络身份与远程攻击面检测
section "8. 网络设备 / IP / 安全服务检查"

echo "  🌐 当前 IP 地址: $(ipconfig getifaddr en0)"
echo "  📡 当前连接 Wi-Fi: $(networksetup -getairportnetwork en0 | awk -F: '{print $2}' | xargs)"
echo "  🧭 MAC 地址: $(ifconfig en0 | awk '/ether/{print $2}')"

# DNS 泄露检测
echo "  🧩 DNS 配置:"
scutil --dns | grep "nameserver" | uniq | sed 's/^/     📶 /'

# 检查远程管理端口是否开放
echo ""
echo "  🔍 检查常见远程服务端口（22/5900）:"
lsof -iTCP -sTCP:LISTEN -n | grep -E ":22|:5900" | sed 's/^/     🚨 /' || ok "未发现常见远程服务监听端口"

# 检查远程激活服务
systemsetup -getremotelogin | grep "On" && warn "远程登录已启用（可被 ssh 控制）" || ok "远程登录未开启"

# 模块 9️⃣：最终风险汇总 & 建议
print_title "🧠 验机结果总结分析"

echo "以下是根据检测结果汇总的全局判断："

# MDM/DEP判断
[[ "$DEP" == "Yes" ]] && risk "该设备注册于 DEP（设备注册计划） → 可能来自企业或教育机构"
[[ "$MDM" == "Yes" ]] && risk "该设备正被 MDM 管理，存在远程限制与配置锁风险"

# 配置锁
[[ -n "$CFGURL" ]] && risk "配置锁 URL 存在，重装系统也会被锁定，请勿购买！"

# 电池健康
[[ "$CYCLE_COUNT" -gt 1000 ]] && warn "电池循环次数超过 1000，存在老化风险"
[[ "$BAT_HEALTH" != "Normal" && "$BAT_HEALTH" != "Good" ]] && risk "电池健康状态异常"

# SMART 状态
[[ "$SMART" != "Verified" && "$SMART" != "" ]] && risk "磁盘 SMART 报警，可能存在硬盘故障"

# SIP 安全
[[ "$SIP_STATUS" != *"enabled"* ]] && risk "SIP 被关闭，系统完整性失效"

# Hook / 越狱
if [ -f "/usr/lib/libhook.dylib" ] || [ -f "/usr/lib/substrate.dylib" ]; then
  risk "越狱工具组件存在 → 有 RootKit 风险"
fi

# Setup Assistant
[ -f /var/db/.AppleSetupDone ] && warn "Setup Assistant 被跳过，可能为跳激活设备"

# Sudoers篡改
[[ "$SUDOERS_HASH" == "" ]] && risk "sudoers 文件读取失败，系统完整性受损"

# 启动项注入
if [[ -n "$DAEMONS" ]]; then
  risk "LaunchDaemons 中存在可疑脚本，可能用于持久化控制"
fi

# 默认 shell 被改
[[ "$DEF_SHELL" != "/bin/bash" && "$DEF_SHELL" != "/bin/zsh" ]] && warn "默认 Shell 异常，需人工排查"

# 远程服务风险
systemsetup -getremotelogin | grep "On" && warn "远程登录已开启，存在 ssh 控制风险"

echo ""
echo -e "${YELLOW}🧾 交易建议：${NC}"

if [[ "$MDM" == "Yes" || "$DEP" == "Yes" || -n "$CFGURL" ]]; then
  echo -e "${RED}❗ 建议中止交易：设备存在企业注册或配置锁，极易被远程锁定${NC}"
elif [[ "$CYCLE_COUNT" -gt 1000 || "$BAT_HEALTH" != "Normal" ]]; then
  echo -e "${YELLOW}⚠️ 建议议价交易：电池存在老化或健康异常${NC}"
else
  echo -e "${GREEN}✅ 设备状态良好，可正常交易${NC}"
fi

echo ""
echo "============================================================="
echo -e "${GREEN}🎉 MacBook 验机完成，感谢使用 Evil0ctal 出品的验机脚本${NC}"
echo "如需保存报告，可使用：sudo ./macos_report.sh | tee 验机报告.txt"
echo "============================================================="