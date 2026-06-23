import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import appIcon from './assets/app-icon.png'

const defaultOptions = {
  profile: 'combined',
  outputDir: '',
  lookbackDays: '',
  maxEvents: 800,
  timeoutSec: 180,
}

const defaultAIConfig = {
  baseUrl: '',
  apiKey: '',
  model: '',
}

const navItems = [
  { id: 'overview', icon: '✦', label: '应急总览', desc: '一键排查与态势摘要' },
  { id: 'host', icon: '▣', label: '主机排查', desc: '账户/进程/网络/文件' },
  { id: 'processes', icon: '⌁', label: '进程清除', desc: '可疑进程定位与终止' },
  { id: 'network', icon: '⟲', label: '网络连接', desc: '外联、监听、代理' },
  { id: 'persistence', icon: '⌘', label: '持久化排查', desc: '服务、计划任务、WMI' },
  { id: 'logs', icon: '≋', label: '日志分析', desc: '登录、PowerShell、系统事件' },
  { id: 'accounts', icon: '◉', label: '账号审计', desc: '管理员组与异常账号' },
  { id: 'files', icon: '◇', label: '文件取证', desc: '落地文件、ADS、Prefetch' },
  { id: 'report', icon: '▤', label: '报告中心', desc: '生成 HTML 文档' },
  { id: 'tools', icon: '▧', label: '应急工具箱', desc: '火绒剑/D盾/Arthas/银狐/Everything' },
  { id: 'settings', icon: '⚙', label: '系统设置', desc: '采集参数与 AI 审计' },
]

const profiles = [
  { id: 'combined', name: '双 Skill 综合排查', desc: '同时运行基础主机排查与企业日志证据链任务，覆盖最全，适合不确定入侵范围时使用。' },
  { id: 'emergency-response', name: '基础主机入侵排查', desc: '只跑账户、进程、网络、持久化、文件系统等主机侧基础任务，速度更快。' },
  { id: 'corporate', name: '企业证据链与日志优先', desc: '只跑安全日志、系统日志、PowerShell、Defender、防火墙等企业溯源任务。' },
]

const severityLabel = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
  pass: '通过',
}


const auditLogTabs = [
  { id: 'all', name: '全部日志', ids: [] },
  { id: 'success', name: '登录成功', ids: [4624, 4648, 4672, 4778] },
  { id: 'failure', name: '登录失败', ids: [4625, 4771, 4776, 4779] },
  { id: 'rdpLogin', name: 'RDP登录', ids: [21, 22, 24, 25] },
  { id: 'rdpConn', name: 'RDP连接', ids: [], realtime: true },
  { id: 'serviceCreate', name: '服务创建', ids: [7045] },
  { id: 'procCreate', name: '创建进程', ids: [4688] },
  { id: 'account', name: '账户操作', ids: [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740] },
  { id: 'service', name: '日志服务关闭', ids: [1100, 6006] },
  { id: 'cleared', name: '审计日志清除', ids: [1102] },
]

const auditLogCategoryById = auditLogTabs.reduce((acc, tab) => {
  tab.ids.forEach((id) => { acc[id] = tab.id })
  return acc
}, {})

const phaseCards = [
  ['0', '初始化准备', '确认权限、时间戳、输出目录'],
  ['1', '账户审计', '管理员组、登录会话、账号变更'],
  ['2', '进程与网络', '异常路径、外联、监听端口'],
  ['3', '持久化排查', '服务、计划任务、WMI、启动项'],
  ['4', '日志溯源', '4624/4625/4672/7045/1102'],
  ['5', '报告输出', '证据片段、风险项、完整日志'],
]

function parseLookbackDays(value) {
  if (value === '' || value === null || value === undefined) return 0
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

function lookbackLabel(value) {
  const days = parseLookbackDays(value)
  return days > 0 ? `${days} 天` : '全部日志'
}

const moduleMap = {
  host: ['主机排查', ['系统版本与补丁检查', '基础信息与权限', '账户与管理员组', '进程命令行', '网络连接', '临时目录与 Prefetch']],
  network: ['网络连接', ['ESTABLISHED 外联', '0.0.0.0 监听', '代理配置', 'DNS 缓存', '路由表']],
  persistence: ['持久化排查', ['注册表 Run/RunOnce', '计划任务', '服务与驱动', 'WMI 永久订阅', '启动文件夹']],
  logs: ['日志分析', ['4624 成功登录', '4625 失败登录', 'RDP 登录/连接', '7045 新服务', '4688 进程创建', '1102 日志清理']],
  accounts: ['账号审计', ['隐藏/克隆账号', '管理员组成员', '异常登录时段', '账号创建启用删除', 'SID 与本地组']],
  files: ['文件取证', ['临时目录文件', '下载目录', 'ADS 数据流', 'WebShell 关键字', 'Prefetch 执行痕迹']],
  tools: ['应急工具箱', ['火绒剑：启动火绒 5.0 独立版 SecAnalysis.exe 做进程/驱动/启动项深度排查', 'D盾：直接启动 WebShell/隐藏账号/克隆账号检查', 'Arthas：打开目录后手动选择 Java 内存马排查方式', '银狐查杀：启动银狐查杀.exe 做专项木马排查', 'Everything：快速搜索可疑样本、WebShell、脚本和落地文件']],
  settings: ['系统设置', ['输出目录', '回溯天数', '事件数量', '单任务超时', 'AI BaseURL / APIKey / 模型']],
}

function App() {
  const [active, setActive] = useState('overview')
  const [status, setStatus] = useState(null)
  const [statusError, setStatusError] = useState('')
  const [options, setOptions] = useState(defaultOptions)
  const [scan, setScan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [processes, setProcesses] = useState([])
  const [processLoading, setProcessLoading] = useState(false)
  const [accounts, setAccounts] = useState([])
  const [accountsLoading, setAccountsLoading] = useState(false)
  const [events, setEvents] = useState([])
  const [eventsLoading, setEventsLoading] = useState(false)
  const [hostInfo, setHostInfo] = useState(null)
  const [hostLoading, setHostLoading] = useState(false)
  const [networkInfo, setNetworkInfo] = useState(null)
  const [networkLoading, setNetworkLoading] = useState(false)
  const [persistenceInfo, setPersistenceInfo] = useState(null)
  const [persistenceLoading, setPersistenceLoading] = useState(false)
  const [tools, setTools] = useState([])
  const [toolsLoading, setToolsLoading] = useState(false)
  const [toolLaunching, setToolLaunching] = useState('')
  const [processSearch, setProcessSearch] = useState('')
  const [processRisk, setProcessRisk] = useState('all')
  const [killBusy, setKillBusy] = useState(null)
  const [deleteBusy, setDeleteBusy] = useState(null)
  const [selectedTask, setSelectedTask] = useState(null)
  const [findingFilter, setFindingFilter] = useState('all')
  const [responseModal, setResponseModal] = useState(false)
  const [aiConfig, setAIConfig] = useState(() => loadAIConfig())
  const [aiAudit, setAIAudit] = useState(null)
  const [aiLoading, setAILoading] = useState(false)
  const [pathMenu, setPathMenu] = useState(null)

  useEffect(() => {
    refreshStatus()
    refreshProcesses(true)
    refreshTools(true)
  }, [])

  useEffect(() => {
    if (!scan?.id || scan.status === 'completed' || scan.status === 'failed') return
    const timer = window.setInterval(async () => {
      try {
        setScan(await api(`/api/scans/${scan.id}`))
      } catch (e) {
        setError(e.message)
      }
    }, 1500)
    return () => window.clearInterval(timer)
  }, [scan?.id, scan?.status])

  useEffect(() => {
    if (active === 'processes') refreshProcesses()
  }, [active])

  useEffect(() => {
    if (active === 'accounts') refreshAccounts()
    if (active === 'logs') refreshEvents()
    if (active === 'host') refreshHost()
    if (active === 'network') refreshNetwork()
    if (active === 'persistence') refreshPersistence()
    if (active === 'tools') refreshTools()
  }, [active])

  useEffect(() => {
    if (scan?.status === 'completed') {
      refreshProcesses(true)
      refreshHost(true)
      refreshAccounts(true)
      refreshEvents(true)
      refreshNetwork(true)
      refreshPersistence(true)
    }
  }, [scan?.status])

  useEffect(() => {
    saveAIConfig(aiConfig)
  }, [aiConfig])

  useEffect(() => {
    if (!pathMenu) return
    const close = () => setPathMenu(null)
    const onKey = (e) => { if (e.key === 'Escape') close() }
    window.addEventListener('click', close)
    window.addEventListener('keydown', onKey)
    window.addEventListener('resize', close)
    window.addEventListener('scroll', close, true)
    return () => {
      window.removeEventListener('click', close)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', close)
      window.removeEventListener('scroll', close, true)
    }
  }, [pathMenu])

  async function refreshStatus() {
    try {
      setStatusError('')
      setStatus(await api('/api/status'))
    } catch (e) {
      setStatusError(e.message)
    }
  }

  async function refreshProcesses(silent = false) {
    setProcessLoading(true)
    setError('')
    try {
      const data = await api('/api/processes')
      setProcesses(data.items || [])
      if (!silent) setNotice(`进程列表已刷新：${data.count || 0} 个进程`)
    } catch (e) {
      setError(e.message)
    } finally {
      setProcessLoading(false)
    }
  }

  async function refreshAccounts(silent = false) {
    setAccountsLoading(true)
    setError('')
    try {
      const data = await api('/api/accounts')
      setAccounts(data.items || [])
      if (!silent) setNotice(`账号列表已刷新：${data.count || 0} 个账号`)
    } catch (e) {
      setError(e.message)
    } finally {
      setAccountsLoading(false)
    }
  }

  async function refreshEvents(silent = false) {
    setEventsLoading(true)
    setError('')
    try {
      const data = await api(`/api/events?days=${parseLookbackDays(options.lookbackDays)}&limit=${Number(options.maxEvents) || 160}`)
      setEvents(data.items || [])
      if (!silent) setNotice(`日志事件已刷新：${data.count || 0} 条`)
    } catch (e) {
      setError(e.message)
    } finally {
      setEventsLoading(false)
    }
  }

  async function refreshHost(silent = false) {
    setHostLoading(true)
    setError('')
    try {
      const data = await api('/api/host')
      setHostInfo(data)
      if (!silent) {
        setNotice(`主机信息已刷新：${data.windowsProductName || 'Windows'} ${data.displayVersion || data.windowsVersion || ''} Build ${data.buildNumber || '未知'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setHostLoading(false)
    }
  }

  async function refreshNetwork(silent = false) {
    setNetworkLoading(true)
    setError('')
    try {
      const data = await api('/api/network')
      setNetworkInfo(data)
      if (!silent) setNotice(`网络信息已刷新：外联 ${data.externalConnections?.length || 0} 条，监听 ${data.listeners?.length || 0} 条`)
    } catch (e) {
      setError(e.message)
    } finally {
      setNetworkLoading(false)
    }
  }

  async function refreshPersistence(silent = false) {
    setPersistenceLoading(true)
    setError('')
    try {
      const data = await api('/api/persistence')
      setPersistenceInfo(data)
      if (!silent) setNotice(`持久化信息已刷新：启动项 ${data.autoruns?.length || 0} 项，计划任务 ${data.tasks?.length || 0} 项，服务 ${data.services?.length || 0} 项`)
    } catch (e) {
      setError(e.message)
    } finally {
      setPersistenceLoading(false)
    }
  }

  async function refreshTools(silent = false) {
    setToolsLoading(true)
    setError('')
    try {
      const data = await api('/api/tools')
      setTools(data.items || [])
      if (!silent) {
        const installed = (data.items || []).filter((x) => x.exists).length
        setNotice(`工具箱已刷新：${installed}/${data.count || 0} 个工具可用`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setToolsLoading(false)
    }
  }

  async function launchTool(tool) {
    if (!tool?.id || !tool.exists) return
    setToolLaunching(tool.id)
    setError('')
    try {
      const result = await api(`/api/tools/${tool.id}/launch`, { method: 'POST', body: JSON.stringify({}) })
      setNotice(result.ok ? `${result.message}：${result.path || ''}` : `启动失败：${result.error || result.message}`)
      await refreshTools(true)
    } catch (e) {
      setError(e.message)
    } finally {
      setToolLaunching('')
    }
  }

  async function runAIAudit() {
    const baseUrl = aiConfig.baseUrl.trim()
    const apiKey = aiConfig.apiKey.trim()
    const model = aiConfig.model.trim()
    if (!baseUrl || !apiKey || !model) {
      setError('请先在系统设置中填写 AI BaseURL、APIKey 和模型。')
      return
    }
    setAILoading(true)
    setError('')
    try {
      const evidence = buildAIEvidence({
        status,
        options,
        scan,
        processes,
        hostInfo,
        accounts,
        events,
        networkInfo: effectiveNetworkInfo,
        persistenceInfo,
        anomalies: anomalyItems,
      })
      const result = await api('/api/ai-audit', {
        method: 'POST',
        body: JSON.stringify({ baseUrl, apiKey, model, outputDir: scan?.outputDir || options.outputDir || '', evidence }),
      })
      setAIAudit(result)
      setNotice(result.reportPath ? `AI 审计完成，HTML 已生成：${result.reportPath}` : 'AI 审计完成，已生成应急专家分析结论。')
    } catch (e) {
      setError(e.message)
    } finally {
      setAILoading(false)
    }
  }

  async function openAIReport() {
    if (!aiAudit?.reportPath) return
    await api('/api/ai-audit/open-report', { method: 'POST', body: JSON.stringify({ path: aiAudit.reportPath }) })
  }

  async function openPathNow(path) {
    if (!path) return
    setError('')
    try {
      const result = await api('/api/open-path', { method: 'POST', body: JSON.stringify({ path }) })
      setNotice(result.message || `已打开目录：${result.dir || path}`)
    } catch (e) {
      setError(`打开所在目录失败：${e.message}`)
    }
  }

  function openPathTarget(path, event) {
    if (!path) return
    if (event?.preventDefault) {
      event.preventDefault()
      event.stopPropagation()
      const width = 210
      const height = 86
      setPathMenu({
        path,
        x: Math.min(event.clientX, window.innerWidth - width - 10),
        y: Math.min(event.clientY, window.innerHeight - height - 10),
      })
      return
    }
    openPathNow(path)
  }

  async function startScan() {
    setBusy(true)
    setError('')
    try {
      const body = {
        ...options,
        lookbackDays: parseLookbackDays(options.lookbackDays),
        maxEvents: Number(options.maxEvents),
        timeoutSec: Number(options.timeoutSec),
      }
      const next = await api('/api/scans', { method: 'POST', body: JSON.stringify(body) })
      setScan(next)
      setNotice('并行采集已启动，完成后会自动生成 HTML 报告')
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  async function generateHtmlReport() {
    if (scan?.status === 'completed' && scan.reportPath) {
      await openReport()
      return
    }
    setActive('report')
    await startScan()
  }

  async function openReport() {
    if (!scan?.id) return
    await api(`/api/scans/${scan.id}/open-report`)
  }

  async function terminateProcess(proc, mode = 'soft') {
    if (!proc || proc.protected) return
    const force = mode === 'force'
    const ok = window.confirm(`确认清除进程 ${proc.name} (PID ${proc.pid})？\n路径：${processDisplayPath(proc)}\n模式：${force ? '强制结束进程树' : '普通结束进程树'}`)
    if (!ok) return
    setKillBusy(proc.pid)
    setError('')
    try {
      const result = await api(`/api/processes/${proc.pid}/terminate`, {
        method: 'POST',
        body: JSON.stringify({ force, tree: true, reason: 'IR process cleanup from client' }),
      })
      setNotice(result.ok ? `已执行：${result.command}` : `执行失败：${result.error || result.output}`)
      await refreshProcesses(true)
    } catch (e) {
      setError(e.message)
    } finally {
      setKillBusy(null)
    }
  }

  // 删除计划任务：Unregister-ScheduledTask，需要 taskName + taskPath 精确定位
  async function deleteTask(task) {
    if (!task || !task.taskName) return
    const fullName = `${task.taskPath || ''}${task.taskName}`
    const ok = window.confirm(`确认删除计划任务？\n名称：${fullName}\n执行：${task.execute || '（无）'} ${task.arguments || ''}\n\n该操作不可恢复，删除前请确认非系统必需任务。`)
    if (!ok) return
    const key = `task::${fullName}`
    setDeleteBusy(key)
    setError('')
    try {
      const result = await api('/api/persistence/tasks/delete', {
        method: 'POST',
        body: JSON.stringify({ taskName: task.taskName, taskPath: task.taskPath || '', reason: 'IR scheduled task removal from client' }),
      })
      if (result.ok) {
        setNotice(result.message || `已删除计划任务：${fullName}`)
        await refreshPersistence(true)
      } else {
        setError(`删除计划任务失败：${result.error || result.output || '未知错误'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleteBusy(null)
    }
  }

  // 删除系统服务：sc.exe delete <name>，关键服务后端有保护名单
  async function deleteService(service) {
    if (!service || !service.name) return
    const ok = window.confirm(`确认删除系统服务？\n服务：${service.displayName || service.name} (${service.name})\n路径：${service.executablePath || service.pathName || '（无）'}\n\n该操作不可恢复，关键系统服务会被拒绝删除。`)
    if (!ok) return
    const key = `svc::${service.name}`
    setDeleteBusy(key)
    setError('')
    try {
      const result = await api('/api/persistence/services/delete', {
        method: 'POST',
        body: JSON.stringify({ name: service.name, reason: 'IR service removal from client' }),
      })
      if (result.ok) {
        setNotice(result.message || `已删除系统服务：${service.name}`)
        await refreshPersistence(true)
      } else {
        setError(`删除系统服务失败：${result.error || result.output || '未知错误'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleteBusy(null)
    }
  }

  // 删除注册表自启值：Remove-ItemProperty，系统关键值默认被后端拒绝
  async function deleteAutorun(autorun) {
    if (!autorun || !autorun.name) return
    const loc = autorun.location || ''
    // 从 location(HKLM:\...)解析 hive 和 keyPath
    const hiveMatch = loc.match(/^(HKLM|HKCU):\\(.*)$/i)
    const hive = hiveMatch ? hiveMatch[1].toUpperCase() : 'HKLM'
    const keyPath = hiveMatch ? hiveMatch[2] : ''
    const isWinlogon = /winlogon/i.test(loc)
    const confirmMsg = isWinlogon
      ? `⚠ 警告：即将删除 Winlogon 关键值（${autorun.name}）！\n位置：${loc}\n值：${autorun.command || '（无）'}\n\n删除 Winlogon\\Shell/Userinit 可能导致系统无法登录。\n请确认已导出 .reg 备份且确认为恶意。需要强制确认：在下方确认框输入 force。`
      : `确认删除注册表自启值？\n名称：${autorun.name}\n位置：${loc}\n值：${autorun.command || '（无）'}\n\n该操作不可恢复，建议先 reg export 导出备份。`
    if (isWinlogon) {
      const force = window.prompt(confirmMsg, '')
      if (force !== 'force') {
        if (force !== null) setError('未输入 force，已取消删除 Winlogon 关键值。')
        return
      }
      autorun = { ...autorun, _force: true }
    } else {
      if (!window.confirm(confirmMsg)) return
    }
    const key = `autorun::${autorun.name}@${loc}`
    setDeleteBusy(key)
    setError('')
    try {
      const result = await api('/api/persistence/autorun/delete', {
        method: 'POST',
        body: JSON.stringify({
          hive,
          keyPath,
          valueName: autorun.name,
          reason: `IR autorun removal from client${autorun._force ? ' force' : ''}`,
        }),
      })
      if (result.ok) {
        setNotice(result.message || `已删除注册表自启值：${autorun.name}`)
        await refreshPersistence(true)
      } else {
        setError(`删除注册表值失败：${result.error || result.output || '未知错误'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleteBusy(null)
    }
  }

  // 删除 WMI 永久订阅：后端先导出对象属性再删除
  async function deleteWmi(wmi) {
    if (!wmi || !wmi.name) return
    const kind = (wmi.kind || '').toLowerCase()
    const kindNorm = /filter/.test(kind) ? 'EventFilter' : /consumer/.test(kind) ? 'Consumer' : /binding/.test(kind) ? 'Binding' : kind
    const ok = window.confirm(`确认删除 WMI 永久订阅？\n类型：${wmi.kind || kindNorm}\n名称：${wmi.name}\n查询/命令：${(wmi.query || wmi.command || '').slice(0, 120)}\n\n后端会先导出对象属性取证，再删除。该操作不可恢复。`)
    if (!ok) return
    const key = `wmi::${wmi.kind}-${wmi.name}`
    setDeleteBusy(key)
    setError('')
    try {
      const result = await api('/api/persistence/wmi/delete', {
        method: 'POST',
        body: JSON.stringify({ kind: kindNorm, name: wmi.name, reason: 'IR WMI subscription removal from client' }),
      })
      if (result.ok) {
        setNotice(result.message || `已删除 WMI 订阅：${wmi.kind}:${wmi.name}`)
        await refreshPersistence(true)
      } else {
        setError(`删除 WMI 订阅失败：${result.error || result.output || '未知错误'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleteBusy(null)
    }
  }

  // 删除启动文件夹文件：后端先备份到 TEMP\ir-deleted-backup 再删除
  async function deleteStartupFile(file) {
    if (!file || !file.fullName) return
    const ok = window.confirm(`确认删除启动文件夹文件？\n路径：${file.fullName}\n大小：${fmtBytes(file.length)}\n\n后端会自动备份到 %TEMP%\\ir-deleted-backup\\ 后删除。`)
    if (!ok) return
    const key = `startup::${file.fullName}`
    setDeleteBusy(key)
    setError('')
    try {
      const result = await api('/api/persistence/startup-file/delete', {
        method: 'POST',
        body: JSON.stringify({ path: file.fullName, reason: 'IR startup file removal from client' }),
      })
      if (result.ok) {
        setNotice(result.message || `已删除启动文件（已备份）：${file.fullName}`)
        await refreshPersistence(true)
      } else {
        setError(`删除启动文件失败：${result.error || result.output || '未知错误'}`)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleteBusy(null)
    }
  }

  const progress = useMemo(() => {
    if (!scan?.tasks?.length) return 0
    return Math.round(((scan.results?.length || 0) / scan.tasks.length) * 100)
  }, [scan])

  const counts = useMemo(() => countSeverities(scan?.findings || []), [scan?.findings])
  const highRiskCount = (counts.critical || 0) + (counts.high || 0)
  const suspiciousProcesses = processes.filter((p) => ['critical', 'high', 'medium'].includes(p.risk)).length
  const findings = useMemo(() => {
    const list = scan?.findings || []
    return findingFilter === 'all' ? list : list.filter((f) => f.severity === findingFilter)
  }, [scan?.findings, findingFilter])
  const filteredProcesses = useMemo(() => {
    const q = processSearch.trim().toLowerCase()
    return processes.filter((p) => {
      const riskOk = processRisk === 'all' || p.risk === processRisk
      const text = `${p.pid} ${p.ppid} ${p.name} ${processDisplayPath(p)} ${p.commandLine} ${p.creationDate} ${p.cpu} ${p.memoryMB} ${(p.reasons || []).join(' ')}`.toLowerCase()
      return riskOk && (!q || text.includes(q))
    })
  }, [processes, processSearch, processRisk])

  const networkFallback = useMemo(() => buildNetworkFallbackFromScan(scan, processes), [scan?.findings, processes])
  const effectiveNetworkInfo = useMemo(() => mergeNetworkInfo(networkInfo, networkFallback), [networkInfo, networkFallback])
  const logLines = useMemo(() => buildLogLines(scan, processes, status), [scan, processes, status])
  const anomalyItems = useMemo(
    () => buildAnomalies(scan, processes, hostInfo, effectiveNetworkInfo, persistenceInfo, accounts, events),
    [scan, processes, hostInfo, effectiveNetworkInfo, persistenceInfo, accounts, events]
  )
  const activeItem = navItems.find((n) => n.id === active) || navItems[0]
  const taskById = useMemo(() => {
    const m = new Map()
    ;(scan?.tasks || []).forEach((t) => m.set(t.id, t))
    return m
  }, [scan?.tasks])
  const availableToolCount = tools.filter((x) => x.exists).length
  const toolTotalCount = tools.length

  return (
    <div className="client-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><img src={appIcon} alt="萤火应急响应工具" /></div>
          <div><b>萤火应急响应工具</b><span>v1.0 · by: firefly</span></div>
        </div>
        <nav className="nav-list">
          {navItems.map((item) => (
            <button key={item.id} className={`nav-item ${active === item.id ? 'active' : ''}`} onClick={() => setActive(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span><b>{item.label}</b><small>{item.desc}</small></span>
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span><i className="led green" />工具箱：{availableToolCount}/{toolTotalCount || 0} 可用</span>
          <span><i className="led blue" />进程：{processes.length || 0} 条</span>
          <span><i className="led red" />高危：{highRiskCount + suspiciousProcesses} 项</span>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="top-title">
            <button className="icon-btn">☰</button>
            <div><h1>{activeItem.label}</h1><p>{activeItem.desc}</p></div>
          </div>
          <div className="top-actions">
            <button className="top-chip" onClick={refreshStatus}>后端：{status ? '在线' : '离线'}</button>
            <button className="top-chip strong" onClick={() => setResponseModal(true)}>查看完整响应</button>
            <button className="icon-btn" onClick={() => document.body.classList.toggle('night')}>◐</button>
            <button className="icon-btn" onClick={generateHtmlReport}>▣</button>
            <div className="avatar">S</div>
          </div>
        </header>

        <section className="content-area">
          {(statusError || error || notice) && (
            <div className="notice-row">
              {statusError && <Notice type="danger" text={`后端连接失败：${statusError}`} />}
              {error && <Notice type="danger" text={error} />}
              {notice && <Notice type="ok" text={notice} />}
            </div>
          )}

          {active === 'overview' && (
            <OverviewPage
              status={status}
              options={options}
              setOptions={setOptions}
              scan={scan}
              busy={busy}
              progress={progress}
              counts={counts}
              highRiskCount={highRiskCount}
              suspiciousProcesses={suspiciousProcesses}
              startScan={startScan}
              generateHtmlReport={generateHtmlReport}
              openReport={openReport}
              logLines={logLines}
              anomalyItems={anomalyItems}
              onNavigate={setActive}
              onOpenResponse={() => setResponseModal(true)}
            />
          )}

          {active === 'processes' && (
            <ProcessesPage
              processes={filteredProcesses}
              allCount={processes.length}
              loading={processLoading}
              search={processSearch}
              setSearch={setProcessSearch}
              risk={processRisk}
              setRisk={setProcessRisk}
              refresh={refreshProcesses}
              terminate={terminateProcess}
              killBusy={killBusy}
            />
          )}

          {active === 'report' && (
            <ReportPage
              scan={scan}
              progress={progress}
              findings={findings}
              findingFilter={findingFilter}
              setFindingFilter={setFindingFilter}
              startScan={generateHtmlReport}
              openReport={openReport}
              setSelectedTask={setSelectedTask}
            />
          )}

          {active !== 'overview' && active !== 'processes' && active !== 'report' && (
            <ModulePage
              active={active}
              scan={scan}
              progress={progress}
              options={options}
              setOptions={setOptions}
              startScan={startScan}
              setActive={setActive}
              anomalyItems={anomalyItems}
              accounts={accounts}
              accountsLoading={accountsLoading}
              events={events}
              eventsLoading={eventsLoading}
              hostInfo={hostInfo}
              hostLoading={hostLoading}
              networkInfo={effectiveNetworkInfo}
              networkLoading={networkLoading}
              persistenceInfo={persistenceInfo}
              persistenceLoading={persistenceLoading}
              tools={tools}
              toolsLoading={toolsLoading}
              toolLaunching={toolLaunching}
              refreshHost={refreshHost}
              refreshAccounts={refreshAccounts}
              refreshEvents={refreshEvents}
              refreshNetwork={refreshNetwork}
              refreshPersistence={refreshPersistence}
              refreshTools={refreshTools}
              deleteTask={deleteTask}
              deleteService={deleteService}
              deleteAutorun={deleteAutorun}
              deleteWmi={deleteWmi}
              deleteStartupFile={deleteStartupFile}
              deleteBusy={deleteBusy}
              launchTool={launchTool}
              openPathTarget={openPathTarget}
              aiConfig={aiConfig}
              setAIConfig={setAIConfig}
              aiAudit={aiAudit}
              aiLoading={aiLoading}
              runAIAudit={runAIAudit}
              openAIReport={openAIReport}
              onOpenResponse={() => setResponseModal(true)}
            />
          )}
        </section>
      </main>

      {selectedTask && (
        <TaskDrawer data={selectedTask} scan={scan} notes={taskById.get(selectedTask.task.id)?.notes} onClose={() => setSelectedTask(null)} />
      )}

      {responseModal && (
        <FullResponseModal
          scan={scan}
          status={status}
          processes={processes}
          hostInfo={hostInfo}
          accounts={accounts}
          events={events}
          networkInfo={effectiveNetworkInfo}
          persistenceInfo={persistenceInfo}
          anomalies={anomalyItems}
          logLines={logLines}
          onClose={() => setResponseModal(false)}
        />
      )}

      {pathMenu && (
        <PathContextMenu
          menu={pathMenu}
          onClose={() => setPathMenu(null)}
          onOpen={(target) => {
            setPathMenu(null)
            openPathNow(target)
          }}
        />
      )}
    </div>
  )
}

function PathContextMenu({ menu, onClose, onOpen }) {
  const stopMenuEvent = (e) => {
    e.preventDefault()
    e.stopPropagation()
  }
  const openTarget = (e) => {
    stopMenuEvent(e)
    onOpen(menu.path)
  }
  return (
    <div
      className="path-context-menu"
      style={{ left: menu.x, top: menu.y }}
      onClick={(e) => e.stopPropagation()}
      onMouseDown={(e) => e.stopPropagation()}
      onPointerDown={(e) => e.stopPropagation()}
      onContextMenu={(e) => e.preventDefault()}
    >
      <button type="button" onMouseDown={(e) => e.preventDefault()} onClick={openTarget}>打开所在目录</button>
      <button type="button" className="ghost" onClick={(e) => { stopMenuEvent(e); onClose() }}>取消</button>
      <small title={menu.path}>{menu.path}</small>
    </div>
  )
}

function OverviewPage({ options, setOptions, scan, busy, progress, counts, highRiskCount, suspiciousProcesses, startScan, generateHtmlReport, openReport, anomalyItems, onNavigate, onOpenResponse }) {
  return (
    <div className="dashboard-grid">
      <section className="left-stack">
        <div className="card scan-card">
          <div className="card-head"><h2>AI 驱动应急排查 <span className="ai-pill">IR</span></h2><span className="status-pill">{scan?.status || 'ready'}</span></div>
          <div className="form-block"><label>输出目录 <em>留空写入系统临时目录，自动保留最近 3 次</em></label><input value={options.outputDir} placeholder="例如 D:\\IR-Reports" onChange={(e) => setOptions({ ...options, outputDir: e.target.value })} /></div>
          <div className="triple-inputs">
          <label><span>回溯天数</span><input type="number" min="0" max="3650" placeholder="留空=全部日志" value={options.lookbackDays} onChange={(e) => setOptions({ ...options, lookbackDays: e.target.value })} /></label>
            <label><span>事件上限</span><input type="number" min="50" max="5000" value={options.maxEvents} onChange={(e) => setOptions({ ...options, maxEvents: e.target.value })} /></label>
            <label><span>超时秒数</span><input type="number" min="30" max="600" value={options.timeoutSec} onChange={(e) => setOptions({ ...options, timeoutSec: e.target.value })} /></label>
          </div>
          <div className="button-row"><button className="primary" disabled={busy || scan?.status === 'running'} onClick={startScan}>▣ 智能排查</button><button className="secondary" disabled={busy || scan?.status === 'running'} onClick={generateHtmlReport}>生成 HTML</button></div>
          <div className="progress-line"><span style={{ width: `${progress}%` }} /></div>
          <div className="quick-stats">
            <Metric icon="◎" label="高危发现" value={highRiskCount} tone="danger" />
            <Metric icon="⌁" label="可疑进程" value={suspiciousProcesses} tone="warn" />
            <Metric icon="▤" label="中低风险" value={(counts.medium || 0) + (counts.low || 0)} tone="ok" />
          </div>
          <div className="report-actions"><a className={`text-link ${scan?.reportPath ? '' : 'disabled'}`} href={scan?.id ? `/api/scans/${scan.id}/report` : '#'} target="_blank" rel="noreferrer">查看 HTML 报告</a><button className="text-link" disabled={!scan?.reportPath} onClick={openReport}>系统打开报告</button></div>
        </div>

        <div className="card phase-card">
          <div className="card-head"><h2>应急阶段</h2><span>{progress}%</span></div>
          <div className="phase-list">
            {phaseCards.map(([n, title, desc], idx) => <div className={`phase ${progress / 20 > idx ? 'done' : ''}`} key={n}><span>{n}</span><div><b>{title}</b><small>{desc}</small></div></div>)}
          </div>
        </div>
      </section>

      <section className="right-stack">
        <AnomalyPanel items={anomalyItems} scan={scan} onNavigate={onNavigate} onOpenResponse={onOpenResponse} />
        <div className="card intel-card">
          <div className="card-head"><h2>专家补充建议</h2><span>VBR</span></div>
          <div className="advice-grid">
            <Advice title="先取证后处置" text="清除进程前先记录 PID、路径、命令行、网络连接和父子进程关系。" />
            <Advice title="高危优先级" text="账户变更、外联、临时目录执行、WMI/计划任务、日志清理优先核验。" />
            <Advice title="横向定损" text="按同账号、同密码、同漏洞、同管理入口扩展检查其它资产。" />
          </div>
        </div>
      </section>
    </div>
  )
}

function ProcessesPage({ processes, allCount, loading, search, setSearch, risk, setRisk, refresh, terminate, killBusy }) {
  const [sort, setSort] = useState({ key: 'risk', dir: 'desc' })
  const [detailProcess, setDetailProcess] = useState(null)
  const sortedProcesses = useMemo(() => sortProcessRows(processes, sort), [processes, sort])
  const changeSort = (key) => setSort((prev) => ({ key, dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc' }))
  const sortMark = (key) => sort.key === key ? (sort.dir === 'desc' ? '↓' : '↑') : '↕'
  return (
    <div className="process-layout">
      <section className="card process-control">
        <div className="card-head">
          <h2>进程清除控制台</h2>
          <div className="process-head-meta"><span className="process-tip">提示：双击进程查看完整详情</span><span>{processes.length} / {allCount} 条</span></div>
        </div>
        <p className="muted">按应急响应思路标记临时目录执行、系统进程伪装、EncodedCommand、LOLBin、异常资源占用等可疑项。</p>
        <div className="filter-row">
          <input value={search} placeholder="搜索 PID / PPID / 名称 / 路径 / 命令行" onChange={(e) => setSearch(e.target.value)} />
          <select value={risk} onChange={(e) => setRisk(e.target.value)}><option value="all">全部风险</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低风险</option><option value="info">受保护</option></select>
          <button className="secondary" onClick={refresh} disabled={loading}>{loading ? '刷新中...' : '刷新进程'}</button>
        </div>
        <div className="process-table-wrap">
          <table className="process-table">
            <colgroup>
              <col className="col-risk" />
              <col className="col-process" />
              <col className="col-pid" />
              <col className="col-ppid" />
              <col className="col-path" />
              <col className="col-created" />
              <col className="col-cpu" />
              <col className="col-memory" />
              <col className="col-command" />
              <col className="col-result" />
              <col className="col-action" />
            </colgroup>
            <thead>
              <tr>
                <th><button className="process-sort" type="button" onClick={() => changeSort('risk')}>风险 <span>{sortMark('risk')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('name')}>名称 <span>{sortMark('name')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('pid')}>PID <span>{sortMark('pid')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('ppid')}>PPID <span>{sortMark('ppid')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('path')}>路径 <span>{sortMark('path')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('creationDate')}>创建时间 <span>{sortMark('creationDate')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('cpu')}>CPU <span>{sortMark('cpu')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('memoryMB')}>内存 <span>{sortMark('memoryMB')}</span></button></th>
                <th><button className="process-sort" type="button" onClick={() => changeSort('commandLine')}>命令行 <span>{sortMark('commandLine')}</span></button></th>
                <th>结果</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {sortedProcesses.map((p) => (
                <tr key={`${p.pid}-${p.name}`} className={`risk-${p.risk}`} onDoubleClick={() => setDetailProcess(p)} title="双击查看完整进程详情">
                  {(() => {
                    const displayPath = processDisplayPath(p)
                    return (
                      <>
                  <td><span className={`risk-badge ${p.risk}`}>{severityLabel[p.risk] || p.risk}</span></td>
                  <td className="process-name-cell"><b title={p.name || ''}>{p.name || '未知进程'}</b><small>{p.protected ? '受保护进程' : '普通进程'}</small></td>
                  <td className="mono">{p.pid || 0}</td>
                  <td className="mono">{p.ppid || 0}</td>
                  <td className="path-cell"><b title={displayPath}>{displayPath}</b></td>
                  <td className="mono created-cell" title={p.creationDate || ''}>{fmtDate(p.creationDate)}</td>
                  <td className="mono">{formatNumber(p.cpu, 2)}</td>
                  <td className="mono">{formatNumber(p.memoryMB, 1)}M</td>
                  <td className="path-cell command-cell"><b title={p.commandLine || ''}>{p.commandLine || '无命令行'}</b></td>
                  <td className="result-cell"><b>{p.protected ? '受保护' : (severityLabel[p.risk] || p.risk)}</b><em>{(p.reasons || []).join('；')}</em></td>
                  <td className="action-cell"><button className="kill soft" disabled={p.protected || killBusy === p.pid} onClick={() => terminate(p, 'soft')}>结束</button><button className="kill force" disabled={p.protected || killBusy === p.pid} onClick={() => terminate(p, 'force')}>强制</button></td>
                      </>
                    )
                  })()}
                </tr>
              ))}
            </tbody>
          </table>
          {!processes.length && <div className="empty-state">暂无进程数据，点击“刷新进程”。</div>}
        </div>
        {detailProcess && <ProcessDetailModal proc={detailProcess} onClose={() => setDetailProcess(null)} terminate={terminate} killBusy={killBusy} />}
      </section>
    </div>
  )
}

function ProcessDetailModal({ proc, onClose, terminate, killBusy }) {
  const displayPath = processDisplayPath(proc)
  const detailRows = [
    ['进程名', proc.name || '未知进程'],
    ['PID / PPID', `${proc.pid || 0} / ${proc.ppid || 0}`],
    ['风险等级', severityLabel[proc.risk] || proc.risk || '未知'],
    ['创建时间', fmtDate(proc.creationDate)],
    ['CPU', formatNumber(proc.cpu, 2)],
    ['内存', `${formatNumber(proc.memoryMB, 1)} MB`],
    ['路径', displayPath],
    ['命令行', proc.commandLine || '无命令行'],
    ['风险原因', (proc.reasons || []).join('；') || '未命中风险规则'],
  ]
  return (
    <div className="process-detail-modal" role="dialog" aria-modal="true" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="process-detail-box">
        <div className="process-detail-head">
          <div><h3>{proc.name || '未知进程'}</h3><p>PID {proc.pid || 0} · PPID {proc.ppid || 0}</p></div>
          <button className="icon-btn" onClick={onClose}>×</button>
        </div>
        <div className="process-detail-grid">
          {detailRows.map(([label, value]) => (
            <div className="process-detail-item" key={label}>
              <small>{label}</small>
              <span title={value}>{value}</span>
            </div>
          ))}
        </div>
        <div className="process-detail-actions">
          <button className="kill soft" disabled={proc.protected || killBusy === proc.pid} onClick={() => terminate(proc, 'soft')}>结束进程树</button>
          <button className="kill force" disabled={proc.protected || killBusy === proc.pid} onClick={() => terminate(proc, 'force')}>强制结束进程树</button>
          <button className="secondary compact" onClick={onClose}>关闭</button>
        </div>
      </div>
    </div>
  )
}

function ReportPage({ scan, progress, findings, findingFilter, setFindingFilter, startScan, openReport, setSelectedTask }) {
  return (
    <div className="report-layout">
      <section className="card report-hero">
        <div><h2>HTML 文档生成</h2><p>扫描完成后自动生成静态 HTML 报告，包含完整日志、快速筛选、可疑项、不安全项、证据片段和处置建议。</p><div className="button-row narrow"><button className="primary" disabled={scan?.status === 'running'} onClick={startScan}>生成 HTML 文档</button><button className="secondary" disabled={!scan?.reportPath} onClick={openReport}>打开报告</button></div></div>
        <div className="report-meter"><b>{progress}%</b><span>{scan?.status || 'ready'}</span></div>
      </section>
      <section className="card">
        <div className="card-head"><h2>风险发现</h2><select value={findingFilter} onChange={(e) => setFindingFilter(e.target.value)}><option value="all">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="pass">通过</option></select></div>
        <div className="finding-grid">{findings.map((f) => <FindingCard key={f.id} finding={f} />)}{!findings.length && <div className="empty-state">暂无发现。先执行一次应急排查。</div>}</div>
      </section>
      <section className="card">
        <div className="card-head"><h2>采集任务</h2><span>{scan?.results?.length || 0}/{scan?.tasks?.length || 0}</span></div>
        <div className="task-grid">{(scan?.tasks || []).map((task) => { const result = (scan?.results || []).find((r) => r.taskId === task.id); return <button className="task-card" key={task.id} onClick={() => setSelectedTask({ task, result })}><span className={`dot ${result?.status || 'pending'}`} /><b>{task.title}</b><small>{task.category} · {result?.status || 'pending'}</small></button> })}</div>
      </section>
    </div>
  )
}

function ModulePage({ active, scan, progress, options, setOptions, startScan, setActive, anomalyItems, accounts, accountsLoading, events, eventsLoading, hostInfo, hostLoading, networkInfo, networkLoading, persistenceInfo, persistenceLoading, tools, toolsLoading, toolLaunching, refreshHost, refreshAccounts, refreshEvents, refreshNetwork, refreshPersistence, refreshTools, deleteTask, deleteService, deleteAutorun, deleteWmi, deleteStartupFile, deleteBusy, launchTool, openPathTarget, aiConfig, setAIConfig, aiAudit, aiLoading, runAIAudit, openAIReport, onOpenResponse }) {
  const [title] = moduleMap[active] || ['应急模块', []]
  const moduleAnomalies = filterModuleAnomalies(active, anomalyItems)
  return (
    <div className="module-grid">
      <section className="right-stack">
        <ModuleDataPanel
          active={active}
          scan={scan}
          options={options}
          setOptions={setOptions}
          accounts={accounts}
          accountsLoading={accountsLoading}
          events={events}
          eventsLoading={eventsLoading}
          hostInfo={hostInfo}
          hostLoading={hostLoading}
          networkInfo={networkInfo}
          networkLoading={networkLoading}
          persistenceInfo={persistenceInfo}
          persistenceLoading={persistenceLoading}
          tools={tools}
          toolsLoading={toolsLoading}
          toolLaunching={toolLaunching}
          refreshHost={refreshHost}
          refreshAccounts={refreshAccounts}
          refreshEvents={refreshEvents}
          refreshNetwork={refreshNetwork}
          refreshPersistence={refreshPersistence}
          refreshTools={refreshTools}
          deleteTask={deleteTask}
          deleteService={deleteService}
          deleteAutorun={deleteAutorun}
          deleteWmi={deleteWmi}
          deleteStartupFile={deleteStartupFile}
          deleteBusy={deleteBusy}
          launchTool={launchTool}
          openPathTarget={openPathTarget}
          aiConfig={aiConfig}
          setAIConfig={setAIConfig}
          aiAudit={aiAudit}
          aiLoading={aiLoading}
          runAIAudit={runAIAudit}
          openAIReport={openAIReport}
          onOpenResponse={onOpenResponse}
        />
        <AnomalyPanel
          title={`${title}异常发现`}
          items={moduleAnomalies}
          scan={scan}
          onNavigate={setActive}
          onOpenResponse={onOpenResponse}
          emptyText={`当前未发现明确的${title}异常。建议查看完整响应，结合业务白名单继续复核该模块原始输出。`}
        />
      </section>
    </div>
  )
}

function ModuleDataPanel({ active, scan, options, setOptions, accounts, accountsLoading, events, eventsLoading, hostInfo, hostLoading, networkInfo, networkLoading, persistenceInfo, persistenceLoading, tools, toolsLoading, toolLaunching, refreshHost, refreshAccounts, refreshEvents, refreshNetwork, refreshPersistence, refreshTools, deleteTask, deleteService, deleteAutorun, deleteWmi, deleteStartupFile, deleteBusy, launchTool, openPathTarget, aiConfig, setAIConfig, aiAudit, aiLoading, runAIAudit, openAIReport, onOpenResponse }) {
  if (active === 'host') {
    return <HostPanel data={hostInfo} loading={hostLoading} refresh={refreshHost} onOpenResponse={onOpenResponse} />
  }
  if (active === 'accounts') {
    return <AccountsPanel accounts={accounts} loading={accountsLoading} refresh={refreshAccounts} onOpenResponse={onOpenResponse} />
  }
  if (active === 'logs') {
    return <EventsPanel events={events} loading={eventsLoading} refresh={refreshEvents} onOpenResponse={onOpenResponse} />
  }
  if (active === 'network') {
    return <NetworkPanel data={networkInfo} loading={networkLoading} refresh={refreshNetwork} openPathTarget={openPathTarget} onOpenResponse={onOpenResponse} />
  }
  if (active === 'persistence') {
    return <PersistencePanel data={persistenceInfo} loading={persistenceLoading} refresh={refreshPersistence} deleteTask={deleteTask} deleteService={deleteService} deleteAutorun={deleteAutorun} deleteWmi={deleteWmi} deleteStartupFile={deleteStartupFile} deleteBusy={deleteBusy} openPathTarget={openPathTarget} onOpenResponse={onOpenResponse} />
  }
  if (active === 'files') {
    return <FilesPanel options={options} onOpenResponse={onOpenResponse} openPathTarget={openPathTarget} />
  }
  if (active === 'tools') {
    return <ToolsPanel tools={tools} loading={toolsLoading} launching={toolLaunching} refresh={refreshTools} launchTool={launchTool} onOpenResponse={onOpenResponse} />
  }
  if (active === 'settings') {
    return <SettingsPanel options={options} setOptions={setOptions} aiConfig={aiConfig} setAIConfig={setAIConfig} aiAudit={aiAudit} aiLoading={aiLoading} runAIAudit={runAIAudit} openAIReport={openAIReport} scan={scan} />
  }
  return <ModuleEvidencePanel active={active} scan={scan} onOpenResponse={onOpenResponse} />
}

function SettingsPanel({ options, setOptions, aiConfig, setAIConfig, aiAudit, aiLoading, runAIAudit, openAIReport, scan }) {
  return (
    <div className="card data-card settings-card">
      <div className="card-head">
        <div><h2>系统设置 <span className="count-pill">AI</span></h2><small>配置采集参数和 AI 审计接口，AI 提示词由后端内置，不在界面展示。</small></div>
      </div>
      <div className="settings-grid">
        <section className="settings-section">
          <div className="detail-title"><b>采集参数</b><span>{scan?.status || 'ready'}</span></div>
          <div className="form-block"><label>输出目录 <em>留空写入系统临时目录，自动保留最近 3 次</em></label><input value={options.outputDir} placeholder="例如 D:\\IR-Reports" onChange={(e) => setOptions({ ...options, outputDir: e.target.value })} /></div>
          <div className="triple-inputs">
          <label><span>回溯天数</span><input type="number" min="0" max="3650" placeholder="留空=全部日志" value={options.lookbackDays} onChange={(e) => setOptions({ ...options, lookbackDays: e.target.value })} /></label>
            <label><span>事件上限</span><input type="number" min="50" max="5000" value={options.maxEvents} onChange={(e) => setOptions({ ...options, maxEvents: e.target.value })} /></label>
            <label><span>超时秒数</span><input type="number" min="30" max="600" value={options.timeoutSec} onChange={(e) => setOptions({ ...options, timeoutSec: e.target.value })} /></label>
          </div>
        </section>

        <section className="settings-section ai-settings">
          <div className="detail-title"><b>AI 审计配置</b><span>OpenAI Compatible</span></div>
          <div className="form-block"><label>BaseURL</label><input value={aiConfig.baseUrl} placeholder="例如 https://api.openai.com/v1" onChange={(e) => setAIConfig({ ...aiConfig, baseUrl: e.target.value })} /></div>
          <div className="form-block"><label>APIKey</label><input type="password" value={aiConfig.apiKey} placeholder="sk-..." onChange={(e) => setAIConfig({ ...aiConfig, apiKey: e.target.value })} /></div>
          <div className="form-block"><label>模型</label><input value={aiConfig.model} placeholder="例如 gpt-4o / deepseek-chat / qwen-plus" onChange={(e) => setAIConfig({ ...aiConfig, model: e.target.value })} /></div>
          <div className="button-row"><button className="primary" disabled={aiLoading} onClick={runAIAudit}>{aiLoading ? 'AI 审计中...' : '开始 AI 审计'}</button></div>
          <p className="profile-hint">会自动汇总网络外联、进程、日志、账号、启动项、计划任务、服务、WMI、异常发现和扫描摘要后提交给模型。</p>
        </section>
      </div>
      <div className="ai-result-box">
        <div className="detail-title"><b>AI 审计结果</b><span>{aiAudit?.model || aiConfig.model || '未调用'}</span></div>
        {aiAudit?.reportPath && (
          <div className="ai-report-actions">
            <a className="secondary compact" href={aiAudit.reportUrl || '#'} target="_blank" rel="noreferrer">查看 AI HTML</a>
            <button className="secondary compact" onClick={openAIReport}>系统打开 HTML</button>
            <span title={aiAudit.reportPath}>{aiAudit.reportPath}</span>
          </div>
        )}
        {aiAudit?.content ? (
          <pre className="ai-result">{aiAudit.content}</pre>
        ) : (
          <div className="empty-state">{aiLoading ? '正在调用 AI 分析当前证据...' : '填写 AI 配置后点击“开始 AI 审计”，这里会显示模型分析结论。'}</div>
        )}
      </div>
    </div>
  )
}

function ToolsPanel({ tools, loading, launching, refresh, launchTool, onOpenResponse }) {
  const available = tools.filter((x) => x.exists).length
  const running = tools.filter((x) => x.running).length
  const missing = tools.length - available
  return (
    <div className="card data-card toolbox-card">
      <div className="card-head">
        <div><h2>应急工具箱 <span className="count-pill">{available}/{tools.length || 0}</span></h2><small>火绒剑、D盾、360 杀毒、银狐查杀、Everything 直接启动；Arthas 打开目录。建议先采集证据再处置。</small></div>
        <div className="mini-actions"><button className="secondary compact" onClick={() => refresh()} disabled={loading}>{loading ? '刷新中' : '刷新工具'}</button><button className="text-link" onClick={onOpenResponse}>完整响应</button></div>
      </div>
      <div className="summary-metrics">
        <div className={`summary-metric ${available ? 'ok' : 'warn'}`}><small>可用工具</small><b>{available}</b><span>已定位本地文件</span></div>
        <div className={`summary-metric ${running ? 'info' : 'ok'}`}><small>运行中</small><b>{running}</b><span>按进程名检测</span></div>
        <div className={`summary-metric ${missing ? 'warn' : 'ok'}`}><small>缺失</small><b>{missing}</b><span>目录未找到</span></div>
      </div>
      <div className="toolbox-grid">
        {tools.map((tool) => (
          <article className={`tool-card ${tool.exists ? '' : 'missing'} ${tool.running ? 'running' : ''}`} key={tool.id}>
            <button className="tool-launch-icon" disabled={!tool.exists || launching === tool.id} onClick={() => launchTool(tool)} title={tool.exists ? `${tool.openMode === 'folder' ? '打开目录' : '启动'} ${tool.name}` : '工具文件不存在'}>
              <ToolIcon tool={tool} />
            </button>
            <div className="tool-card-main">
              <div className="tool-card-title">
                <div><b>{tool.name}</b><span>{tool.category} · {tool.scenario}</span></div>
                <span className={`tool-state ${tool.running ? 'running' : tool.exists ? 'ready' : 'missing'}`}>{tool.running ? '运行中' : tool.exists ? (tool.openMode === 'folder' ? '可打开' : '可启动') : '缺失'}</span>
              </div>
              <p>{tool.description}</p>
              <div className="tool-tags">{(tool.tags || []).map((tag) => <span key={tag}>{tag}</span>)}</div>
              <div className="tool-path" title={tool.path || ''}>{tool.path || '未找到工具文件，请确认目录是否在应急响应工具根目录下。'}</div>
              <div className="tool-advice"><b>应急建议：</b>{tool.advice}</div>
              <div className="tool-actions">
                <button className="primary" disabled={!tool.exists || launching === tool.id} onClick={() => launchTool(tool)}>{launching === tool.id ? '处理中...' : (tool.openMode === 'folder' ? '打开目录' : `启动 ${tool.name}`)}</button>
                <span>{tool.needAdmin ? '建议管理员权限运行' : '普通权限可使用'} · {tool.openMode === 'folder' ? '入口' : '进程'}：{tool.processName || '按工具自身显示'}</span>
              </div>
            </div>
          </article>
        ))}
        {!tools.length && <div className="empty-state">{loading ? '正在定位工具目录...' : '暂无工具箱数据，点击“刷新工具”。'}</div>}
      </div>
    </div>
  )
}

function ToolIcon({ tool }) {
  if (tool?.iconData) {
    return <img src={tool.iconData} alt={tool.name || 'tool'} />
  }
  return <span>{tool?.icon || '萤'}</span>
}

function HostPanel({ data, loading, refresh, onOpenResponse }) {
  const hotfixes = data?.hotfixes || []
  const ips = data?.ipAddresses || []
  const versionLine = data ? `${data.windowsProductName || 'Windows'} ${data.displayVersion || data.windowsVersion || ''}`.trim() : '未读取'
  const buildLine = data ? `Build ${data.buildNumber || '未知'}${data.ubr ? `.${data.ubr}` : ''}` : '未读取'
  return (
    <div className="card data-card">
      <div className="card-head">
        <div><h2>主机系统版本检查 <span className={`risk-badge ${data?.risk || 'info'}`}>{severityLabel[data?.risk] || '待检查'}</span></h2><small>Windows 版本、Build、权限、补丁、IP 配置已结构化提取</small></div>
        <div className="mini-actions"><button className="secondary compact" onClick={() => refresh()} disabled={loading}>{loading ? '刷新中' : '刷新主机'}</button><button className="text-link" onClick={onOpenResponse}>完整响应</button></div>
      </div>
      <div className="summary-metrics">
        <div className="summary-metric info"><small>系统版本</small><b title={versionLine}>{versionLine}</b><span>{buildLine}</span></div>
        <div className={`summary-metric ${data?.isAdmin ? 'ok' : 'warn'}`}><small>当前权限</small><b>{data?.isAdmin ? '管理员' : '普通权限'}</b><span>{data?.currentUser || '未知用户'}</span></div>
        <div className="summary-metric info"><small>补丁/IP</small><b>{hotfixes.length}/{ips.length}</b><span>最近补丁 / IPv4</span></div>
      </div>
      <div className="detail-list">
        <section className="detail-section">
          <div className="detail-title"><b>系统版本与硬件</b><span>{data ? '已检查' : '未采集'}</span></div>
          {data ? (
            <div className="host-kv-grid">
              <HostKV label="主机名" value={data.hostname} />
              <HostKV label="系统版本" value={versionLine} />
              <HostKV label="Build/UBR" value={buildLine} />
              <HostKV label="架构" value={data.architecture} />
              <HostKV label="域/工作组" value={data.domain} />
              <HostKV label="厂商型号" value={`${data.manufacturer || '未知'} ${data.model || ''}`.trim()} />
              <HostKV label="安装时间" value={fmtDate(data.installDate)} />
              <HostKV label="最近启动" value={fmtDate(data.lastBootTime)} />
              <HostKV label="PowerShell" value={data.powerShellVersion} />
            </div>
          ) : (
            <div className="empty-state">{loading ? '正在读取系统版本...' : '暂无主机数据，点击“刷新主机”。'}</div>
          )}
        </section>
        <section className="detail-section">
          <div className="detail-title"><b>权限与风险结论</b><span>{data?.reasons?.length || 0} 条</span></div>
          {data ? <ConfigRow title={data.currentUser || '未知用户'} value={`SID ${data.userSid || '未知'} · ${data.isAdmin ? '管理员权限' : '普通权限'}`} risk={data.risk || 'info'} reasons={data.reasons} /> : <div className="empty-state">暂无权限数据。</div>}
        </section>
        <section className="detail-section">
          <div className="detail-title"><b>IPv4 配置</b><span>{ips.length} 个地址</span></div>
          {ips.map((ip) => <ConfigRow key={`${ip.interfaceAlias}-${ip.ipAddress}`} title={ip.interfaceAlias || '未知网卡'} value={`${ip.ipAddress}/${ip.prefixLength || 0}`} risk="info" reasons={['本机 IPv4 地址']} />)}
          {!ips.length && <div className="empty-state">{loading ? '正在读取 IP 配置...' : '未读取到 IPv4 地址。'}</div>}
        </section>
        <section className="detail-section">
          <div className="detail-title"><b>最近补丁</b><span>{hotfixes.length} 条</span></div>
          {hotfixes.slice(0, 20).map((h) => <ConfigRow key={`${h.hotFixId}-${h.installedOn}`} title={h.hotFixId || 'Hotfix'} value={`${h.description || '补丁'} · ${fmtDate(h.installedOn)} · ${h.installedBy || '未知安装者'}`} risk="info" reasons={['最近安装的系统补丁']} />)}
          {!hotfixes.length && <div className="empty-state">{loading ? '正在读取补丁...' : '未读取到补丁列表。'}</div>}
        </section>
      </div>
    </div>
  )
}

function HostKV({ label, value }) {
  return <div className="host-kv"><small>{label}</small><b title={value || ''}>{value || '未知'}</b></div>
}

function AccountsPanel({ accounts, loading, refresh, onOpenResponse }) {
  const admins = accounts.filter((x) => x.admin).length
  const enabled = accounts.filter((x) => x.enabled).length
  const hidden = accounts.filter((x) => isHiddenAccount(x)).length
  return (
    <div className="card data-card">
      <div className="card-head">
        <div><h2>本地账号列表 <span className="count-pill">{accounts.length}</span></h2><small>启用 {enabled} 个 · 管理员 {admins} 个 · 隐藏 {hidden} 个</small></div>
        <div className="mini-actions"><button className="secondary compact" onClick={() => refresh()} disabled={loading}>{loading ? '刷新中' : '刷新账号'}</button><button className="text-link" onClick={onOpenResponse}>完整响应</button></div>
      </div>
      <div className="account-list">
        <table className="account-table">
          <thead>
            <tr>
              <th className="account-index"></th>
              <th>名称</th>
              <th>状态</th>
              <th>启用</th>
              <th>标记</th>
              <th>描述</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a, idx) => {
              const hiddenAccount = isHiddenAccount(a)
              const description = a.description || (a.reasons || []).join('；') || '无描述'
              return (
                <tr className={`account-table-row severity-${a.risk}`} key={a.sid || a.name} title={`SID：${a.sid || '未知'}\n最后登录：${fmtDate(a.lastLogon)}\n密码修改：${fmtDate(a.passwordLastSet)}\n风险：${(a.reasons || []).join('；')}`}>
                  <td className="account-index">{idx + 1}</td>
                  <td><b className="account-name">{a.name}</b></td>
                  <td><span className={`account-role ${a.admin ? 'admin' : 'normal'}`}>{a.admin ? '管理员' : '普通账户'}</span></td>
                  <td><StateCell value={a.enabled} yes="是" no="否" /></td>
                  <td><span className={`account-mark ${hiddenAccount ? 'hidden' : 'normal'}`}>{hiddenAccount ? '隐藏账户' : '正常'}</span></td>
                  <td><span className="account-desc" title={description}>{description}</span></td>
                </tr>
              )
            })}
            {!accounts.length && (
              <tr><td colSpan="6" className="audit-empty">{loading ? '正在读取本地账号...' : '暂无账号数据，点击“刷新账号”。'}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}


function FlatTabs({ tabs, active, onChange }) {
  return (
    <div className="audit-tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          type="button"
          role="tab"
          aria-selected={active === tab.id}
          className={`audit-tab ${active === tab.id ? 'active' : ''}`}
          key={tab.id}
          onClick={() => onChange(tab.id)}
        >
          <span>{tab.name}</span>
          <em>{tab.count ?? 0}</em>
        </button>
      ))}
    </div>
  )
}

function FlatToolbar({ loading, onRefresh, filter, onFilter, placeholder, visible, total, summary, onOpenResponse }) {
  return (
    <div className="audit-toolbar">
      {onRefresh && (
        <button className={`audit-refresh ${loading ? 'loading' : ''}`} onClick={() => onRefresh()} disabled={loading} title="刷新" aria-label="刷新">
          <span>↻</span>
        </button>
      )}
      <input className="audit-filter" value={filter} onChange={(e) => onFilter(e.target.value)} placeholder={placeholder || '关键字过滤'} />
      <div className="audit-status">
        <b>{visible} / {total}</b>
        <span>{summary || '显示 / 总计'}</span>
      </div>
      {onOpenResponse && <button className="text-link" onClick={onOpenResponse}>完整响应</button>}
    </div>
  )
}

function FlatAuditTable({ columns, rows, loading, emptyText, rowKey, rowTitle, rowPath, openPathTarget }) {
  return (
    <div className="audit-table-wrap">
      <table className="audit-table flat-table">
        <thead>
          <tr>{columns.map((c) => <th key={c.key || c.label} style={c.width ? { width: c.width } : undefined}>{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => {
            const targetPath = rowPath?.(row) || ''
            return (
              <tr
                className={`audit-row severity-${row.risk || 'low'}`}
                key={rowKey ? rowKey(row, idx) : idx}
                title={rowTitle ? rowTitle(row) : targetPath}
                onContextMenu={(e) => { if (targetPath && openPathTarget) openPathTarget(targetPath, e) }}
              >
                {columns.map((c) => <td key={c.key || c.label}>{c.render ? c.render(row, idx) : row[c.key]}</td>)}
              </tr>
            )
          })}
          {!rows.length && (
            <tr><td colSpan={columns.length} className="audit-empty">{loading ? '正在加载...' : (emptyText || 'No Data')}</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function SignCell({ status, signer }) {
  const valid = String(status || '').toLowerCase() === 'valid'
  const known = !!String(status || '').trim()
  return <span className={`sign-cell ${valid ? 'yes' : 'no'}`} title={signer || status || ''}>{valid ? '是' : known ? '否' : '未知'}</span>
}

function StateCell({ value, yes = '启用', no = '禁用' }) {
  const enabled = value === true || /^(ready|running|enabled|auto|automatic|manual)$/i.test(String(value || ''))
  return <span className={`state-cell ${enabled ? 'enabled' : 'disabled'}`}>{enabled ? yes : no}</span>
}

function flatFilterRows(rows, filter, pick) {
  const q = String(filter || '').trim().toLowerCase()
  if (!q) return rows
  return rows.filter((row, idx) => String(pick(row, idx) || '').toLowerCase().includes(q))
}

function pathSourceLabel(location) {
  const text = String(location || '').toLowerCase()
  if (text.includes('hklm')) return 'hklm'
  if (text.includes('hkcu')) return 'hkcu'
  if (text.includes('startup')) return 'startup'
  if (text.includes('wow6432node')) return 'wow64'
  return location || '未知'
}

function sortRowsByRisk(rows) {
  return [...(rows || [])].sort((a, b) => severityWeight(b?.risk) - severityWeight(a?.risk))
}

function isListenConnection(row) {
  return /^listen$/i.test(String(row?.state || ''))
}

function rowReasons(row) {
  return (row?.reasons || []).filter(Boolean).join('；')
}

function isHiddenAccount(account) {
  return !!account?.hidden || String(account?.name || '').endsWith('$') || (account?.reasons || []).some((r) => String(r || '').includes('隐藏账号'))
}

function EventsPanel({ events, loading, refresh, onOpenResponse }) {
  const [activeTab, setActiveTab] = useState('all')
  const [keyword, setKeyword] = useState('')
  const [sortAsc, setSortAsc] = useState(false)
  const [rdpSessions, setRdpSessions] = useState([])
  const [rdpLoading, setRdpLoading] = useState(false)
  const auditRows = useMemo(() => (events || []).map(toAuditEventRow), [events])
  const high = auditRows.filter((x) => ['critical', 'high'].includes(x.risk)).length
  // RDP连接是实时会话快照，独立于事件日志，按需拉取 /api/rdp-sessions
  const refreshRdpSessions = useCallback(async () => {
    setRdpLoading(true)
    try {
      const data = await api('/api/rdp-sessions')
      setRdpSessions(data.items || [])
    } catch (e) {
      setRdpSessions([])
    } finally {
      setRdpLoading(false)
    }
  }, [])
  // 切到 RDP连接 tab 时自动拉取一次
  useEffect(() => {
    if (activeTab === 'rdpConn') refreshRdpSessions()
  }, [activeTab, refreshRdpSessions])
  const tabItems = useMemo(() => auditLogTabs.map((tab) => ({
    ...tab,
    count: tab.id === 'all' ? auditRows.length : tab.id === 'rdpConn' ? rdpSessions.length : auditRows.filter((x) => x.category === tab.id).length,
  })), [auditRows, rdpSessions])
  const visibleRows = useMemo(() => {
    const q = keyword.trim().toLowerCase()
    return auditRows
      .filter((row) => activeTab === 'all' || row.category === activeTab)
      .filter((row) => !q || [row.user, row.ip, row.port, row.eventId, row.loginType, row.title, row.provider, row.log, row.commandLine, row.serviceName].some((v) => String(v || '').toLowerCase().includes(q)))
      .sort((a, b) => {
        const av = new Date(a.timeRaw || 0).getTime() || 0
        const bv = new Date(b.timeRaw || 0).getTime() || 0
        return sortAsc ? av - bv : bv - av
      })
  }, [auditRows, activeTab, keyword, sortAsc])
  const activeMeta = tabItems.find((x) => x.id === activeTab) || tabItems[0]
  // RDP连接 tab：用会话快照数据 + 专用列
  const rdpVisible = useMemo(() => {
    const q = keyword.trim().toLowerCase()
    return (rdpSessions || []).filter((s) => !q || [s.userName, s.sessionName, s.id, s.state, s.idleTime, s.logonTime].some((v) => String(v || '').toLowerCase().includes(q)))
  }, [rdpSessions, keyword])
  const rdpColumns = [
    { label: '用户名', render: (row) => <b>{row.userName || '-'}</b> },
    { label: '会话名', width: '140px', render: (row) => row.sessionName || '-' },
    { label: '会话ID', width: '100px', render: (row) => row.id || '-' },
    { label: '状态', width: '120px', render: (row) => <span className={`audit-id ${String(row.state).toLowerCase() === 'active' ? 'high' : 'low'}`}>{row.state || '-'}</span> },
    { label: '空闲时间', width: '140px', render: (row) => row.idleTime || '-' },
    { label: '登录时间', width: '220px', render: (row) => <time>{fmtDate(row.logonTime)}</time> },
  ]
  const columns = [
    { label: <button className="audit-sort" type="button" onClick={() => setSortAsc((x) => !x)}>时间 <span>{sortAsc ? '↑' : '↓'}</span></button>, width: '220px', render: (row) => <time>{row.time}</time> },
    { label: '事件ID', width: '100px', render: (row) => <span className={`audit-id ${row.risk}`}>{row.eventId || 'LOG'}</span> },
    { label: '事件/登录类型', width: '200px', render: (row) => row.loginType || row.title || '-' },
    // 账户操作/日志服务关闭/审计日志清除/服务创建/进程创建 本身就没有源 IP，显示“本地/—”而非问号
    { label: 'IP地址', width: '160px', render: (row) => row.ip || (noIpEvent(row) ? '本地' : '?') },
    { label: '用户名/详情', render: (row) => <><b>{row.user || '-'}</b>{row.serviceName ? <small>服务 {row.serviceName}{row.imagePath ? ` · ${row.imagePath}` : ''}</small> : row.commandLine ? <small title={row.commandLine}>命令 {truncateMid(row.commandLine, 80)}</small> : <small>{row.log} · {row.provider || 'provider unknown'}</small>}</> },
  ]
  const isRdpConn = activeTab === 'rdpConn'
  return (
    <div className="card data-card audit-log-panel">
      <FlatTabs tabs={tabItems} active={activeTab} onChange={setActiveTab} />
      <FlatToolbar loading={isRdpConn ? rdpLoading : loading} onRefresh={isRdpConn ? refreshRdpSessions : refresh} filter={keyword} onFilter={setKeyword} placeholder={isRdpConn ? '用户名 / 会话名过滤' : '用户名 / IP / Event ID / 命令行过滤'} visible={isRdpConn ? rdpVisible.length : visibleRows.length} total={isRdpConn ? rdpSessions.length : auditRows.length} summary={`${activeMeta?.name || '全部日志'}${isRdpConn ? '' : ` · 高危 ${high} 条`} · 总计 ${isRdpConn ? rdpSessions.length : events.length} 条`} onOpenResponse={onOpenResponse} />
      {isRdpConn ? (
        <FlatAuditTable columns={rdpColumns} rows={rdpVisible} loading={rdpLoading} emptyText="无活动会话（未启用 RDP 或无远程连接）" rowKey={(row, idx) => `rdp-${row.userName}-${row.id}-${idx}`} rowTitle={(row) => `用户：${row.userName} · 状态：${row.state} · 登录时间：${fmtDate(row.logonTime)}`} />
      ) : (
        <FlatAuditTable columns={columns} rows={visibleRows} loading={loading} emptyText="No Data" rowKey={(row, idx) => `${row.eventId}-${row.timeRaw}-${row.user}-${idx}`} rowTitle={(row) => row.summary} />
      )}
    </div>
  )
}

function NetworkPanel({ data, loading, refresh, openPathTarget, onOpenResponse }) {
  const [activeTab, setActiveTab] = useState('connections')
  const [filter, setFilter] = useState('')
  const [expandedPids, setExpandedPids] = useState({})
  const connections = data?.connections || []
  const activeConnections = connections.filter((x) => !isListenConnection(x))
  const external = data?.externalConnections || []
  const dnsCache = sortRowsByRisk(data?.dnsCache || [])
  const dnsServers = data?.dnsServers || []
  const routes = data?.routes || []
  const proxies = data?.proxies || []
  const modules = sortRowsByRisk(data?.modules || [])
  const externalIps = Array.from(new Set(external.map((x) => x.remoteAddress).filter(Boolean))).slice(0, 120)
  const suspiciousDns = dnsCache.filter((x) => x.risk !== 'low')
  const riskyDnsServers = dnsServers.filter((x) => x.risk !== 'low')
  const riskyProxies = proxies.filter((x) => x.risk !== 'low')
  const riskyRoutes = routes.filter((x) => x.risk !== 'low')
  const visibleRoutes = sortRowsByRisk(routes)
    .filter((r, idx) => r.risk !== 'low' || r.destinationPrefix === '0.0.0.0/0' || idx < 30)
    .slice(0, 200)
  const tabItems = [
    { id: 'connections', name: '网络连接', count: external.length },
    { id: 'dns', name: 'DNS缓存', count: dnsCache.length },
    { id: 'config', name: '网络配置', count: dnsServers.length + routes.length + proxies.length },
    { id: 'dll', name: 'DLL信息', count: modules.length },
  ]
  const sourceRows = {
    connections: external,
    dns: dnsCache,
    config: [...dnsServers, ...proxies, ...routes],
    dll: modules,
  }[activeTab] || []
  const rows = flatFilterRows(sourceRows, filter, (row) => JSON.stringify(row))
  const activeName = tabItems.find((x) => x.id === activeTab)?.name || '网络连接'
  const orderedConnections = sortRowsByRisk(rows).sort((a, b) => Number(Boolean(b.external)) - Number(Boolean(a.external)))
  const externalConnectionRows = orderedConnections.filter((c) => c.external)
  const externalGroups = buildExternalPidGroups(externalConnectionRows)
  const filteredDns = activeTab === 'dns' ? rows : dnsCache
  const dllColumns = [
    { label: 'ID', width: '70px', render: (_, idx) => idx + 1 },
    { label: '进程数', width: '100px', render: (r) => r.processCount || 1 },
    { label: '进程id', width: '120px', render: (r) => r.pid || '?' },
    { label: '进程名', width: '190px', render: (r) => r.process || '?' },
    { label: '进程路径', width: '360px', render: (r) => <span title={r.processPath}>{r.processPath || '?'}</span> },
    { label: '签名', width: '100px', render: (r) => <SignCell status={r.signatureStatus} signer={r.signer} /> },
    { label: 'DLL路径', render: (r) => <span title={r.dllPath}>{r.dllPath || '?'}</span> },
  ]
  return (
    <div className="card data-card network-tabs-card">
      <FlatTabs tabs={tabItems} active={activeTab} onChange={setActiveTab} />
      <FlatToolbar loading={loading} onRefresh={refresh} filter={filter} onFilter={setFilter} placeholder={activeTab === 'dll' ? 'dll 路径过滤' : activeTab === 'dns' ? '域名 / 解析值过滤' : '外联 IP / 进程 / 路径过滤'} visible={rows.length} total={sourceRows.length} summary={`${activeName} · 外联 ${external.length} 条 · DNS疑似 ${suspiciousDns.length} 条`} onOpenResponse={onOpenResponse} />

      {activeTab === 'connections' && (
        <>
          <div className="summary-metrics">
            <div className={`summary-metric ${external.length ? 'warn' : 'ok'}`}><small>外联连接</small><b>{external.length}</b><span>{externalIps.length ? `${externalIps.length} 个外联 IP` : '未发现外联 IP'}</span></div>
            <div className={`summary-metric ${activeConnections.length ? 'info' : 'ok'}`}><small>网络连接</small><b>{activeConnections.length}</b><span>已排除监听端口</span></div>
            <div className={`summary-metric ${riskyDnsServers.length || riskyProxies.length || riskyRoutes.length ? 'warn' : 'ok'}`}><small>配置风险</small><b>{riskyDnsServers.length + riskyProxies.length + riskyRoutes.length}</b><span>DNS / 代理 / 路由</span></div>
          </div>
          <div className="detail-list">
            <section className="detail-section">
              <div className="detail-title"><b>外联网络连接明细</b><span>{externalGroups.length} 个 PID/进程组 · {externalConnectionRows.length} 条</span></div>
              {externalGroups.slice(0, 120).map((group) => (
                <ConnectionGroup
                  key={group.key}
                  group={group}
                  expanded={Boolean(expandedPids[group.key])}
                  onToggle={() => setExpandedPids((prev) => ({ ...prev, [group.key]: !prev[group.key] }))}
                  openPathTarget={openPathTarget}
                />
              ))}
              {!externalConnectionRows.length && <div className="empty-state">{loading ? '正在读取外联网络连接...' : '未发现外联网络连接。'}</div>}
            </section>
            <section className="detail-section">
              <div className="detail-title"><b>风险摘要</b><span>{riskyDnsServers.length + riskyProxies.length + riskyRoutes.length + suspiciousDns.length} 项</span></div>
              {riskyDnsServers.map((d) => <ConfigRow key={`summary-dns-${d.interfaceAlias}`} title={`异常 DNS：${(d.serverAddresses || []).join(', ') || '未知'}`} value={`网卡：${d.interfaceAlias || '未知'}`} risk={d.risk} reasons={d.reasons} />)}
              {riskyProxies.map((p) => <ConfigRow key={`summary-proxy-${p.scope}`} title={`代理配置：${p.scope}`} value={p.enabled ? (p.server || p.raw || '代理已启用') : (p.server || p.raw || '代理未启用')} risk={p.risk} reasons={p.reasons} />)}
              {riskyRoutes.slice(0, 40).map((r) => <ConfigRow key={`summary-route-${r.destinationPrefix}-${r.nextHop}-${r.interfaceAlias}`} title={`路由：${r.destinationPrefix} -> ${r.nextHop || 'On-link'}`} value={`${r.interfaceAlias || '未知网卡'} · metric ${r.routeMetric} · ${r.protocol || '未知协议'}`} risk={r.risk} reasons={r.reasons} />)}
              {suspiciousDns.slice(0, 60).map((d) => <ConfigRow key={`summary-cache-${d.entry}-${d.name}-${d.data}`} title={`可疑 DNS：${d.name || d.entry}`} value={`${d.type || 'DNS'} · ${d.data || '无解析值'} · TTL ${d.timeToLive || 0}`} risk={d.risk} reasons={d.reasons} />)}
              {!(riskyDnsServers.length + riskyProxies.length + riskyRoutes.length + suspiciousDns.length) && <div className="empty-state">未命中网络配置和 DNS 风险规则。</div>}
            </section>
          </div>
        </>
      )}

      {activeTab === 'dns' && (
        <div className="detail-list">
          <section className="detail-section">
            <div className="detail-title"><b>DNS 缓存</b><span>疑似 {suspiciousDns.length} 条 / 全部 {dnsCache.length} 条</span></div>
            <small className="section-hint">已按风险排序，疑似动态域名、DNSLog、OOB、隧道域名排在前面；筛选不裁剪结果。</small>
            {filteredDns.map((d) => <ConfigRow key={`${d.entry}-${d.name}-${d.data}-${d.timeToLive}`} title={d.name || d.entry || '未知域名'} value={`${d.type || 'DNS'} · ${d.data || '无解析值'} · TTL ${d.timeToLive || 0}`} risk={d.risk} reasons={d.reasons} onIntel={() => openThreatIntel('domain', d.name || d.entry)} />)}
            {!filteredDns.length && <div className="empty-state">{loading ? '正在读取 DNS 缓存...' : '未读取到 DNS 缓存记录。'}</div>}
          </section>
        </div>
      )}

      {activeTab === 'config' && (
        <div className="detail-list">
          <section className="detail-section">
            <div className="detail-title"><b>DNS 服务器 / 代理</b><span>{dnsServers.length + proxies.length} 项</span></div>
            {dnsServers.map((d) => <ConfigRow key={d.interfaceAlias} title={d.interfaceAlias || '未知网卡'} value={(d.serverAddresses || []).join(', ') || '无'} risk={d.risk} reasons={d.reasons} />)}
            {proxies.map((p) => <ConfigRow key={p.scope} title={p.scope} value={p.enabled ? (p.server || p.raw || '代理已启用') : (p.server || p.raw || '未启用')} risk={p.risk} reasons={p.reasons} />)}
            {!dnsServers.length && !proxies.length && <div className="empty-state">{loading ? '正在读取网络配置...' : '未读取到 DNS 服务器或代理配置。'}</div>}
          </section>
          <section className="detail-section">
            <div className="detail-title"><b>路由配置</b><span>{visibleRoutes.length} 条 / 全部 {routes.length} 条</span></div>
            {visibleRoutes.map((r) => <ConfigRow key={`${r.destinationPrefix}-${r.nextHop}-${r.interfaceAlias}`} title={`${r.destinationPrefix} -> ${r.nextHop || 'On-link'}`} value={`${r.interfaceAlias || '未知网卡'} · metric ${r.routeMetric} · ${r.protocol || '未知协议'} · ${r.state || 'Unknown'}`} risk={r.risk} reasons={r.reasons} />)}
            {!visibleRoutes.length && <div className="empty-state">{loading ? '正在读取路由表...' : '未读取到 IPv4 路由表。'}</div>}
          </section>
        </div>
      )}

      {activeTab === 'dll' && (
        <div className="flat-audit-panel network-audit-panel">
          <FlatAuditTable columns={dllColumns} rows={rows} loading={loading} emptyText="未读取到 DLL 信息；请点击刷新，普通权限可能只能读取部分进程模块。" rowKey={(row, idx) => `${row.dllPath || row.processPath}-${row.pid}-${idx}`} rowTitle={(row) => rowReasons(row)} rowPath={(row) => row.dllPath || row.processPath} openPathTarget={openPathTarget} />
        </div>
      )}
    </div>
  )
}

function buildExternalPidGroups(connections) {
  const groups = new Map()
  ;(connections || []).forEach((c) => {
    const pid = c.pid || 0
    const key = `pid-${pid || 'unknown'}-${c.process || 'unknown'}-${c.path || ''}`
    const existing = groups.get(key) || {
      key,
      pid,
      process: c.process || '未知进程',
      path: c.path || '',
      commandLine: c.commandLine || '',
      risk: c.risk || 'medium',
      reasons: [],
      connections: [],
      ips: new Set(),
      ports: new Set(),
    }
    existing.connections.push(c)
    if (c.remoteAddress) existing.ips.add(c.remoteAddress)
    if (c.remotePort) existing.ports.add(c.remotePort)
    if (!existing.path && c.path) existing.path = c.path
    if (!existing.commandLine && c.commandLine) existing.commandLine = c.commandLine
    if (severityWeight(c.risk) > severityWeight(existing.risk)) existing.risk = c.risk
    ;(c.reasons || []).forEach((reason) => {
      if (reason && !existing.reasons.includes(reason)) existing.reasons.push(reason)
    })
    groups.set(key, existing)
  })
  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      ips: Array.from(group.ips).sort(),
      ports: Array.from(group.ports).sort((a, b) => Number(a) - Number(b)),
      connections: group.connections.sort((a, b) => String(a.remoteAddress).localeCompare(String(b.remoteAddress)) || (a.remotePort || 0) - (b.remotePort || 0)),
    }))
    .sort((a, b) => severityWeight(b.risk) - severityWeight(a.risk) || b.connections.length - a.connections.length || Number(b.pid || 0) - Number(a.pid || 0))
}

function ConnectionGroup({ group, expanded, onToggle, openPathTarget }) {
  const targetPath = group.path || group.commandLine || ''
  const previewIps = group.ips.slice(0, 4).join(', ')
  const hiddenCount = Math.max(0, group.ips.length - 4)
  return (
    <article className={`connection-group severity-${group.risk}`} title={targetPath ? '右键选择打开所在目录' : ''} onContextMenu={(e) => { if (targetPath) openPathTarget?.(targetPath, e) }}>
      <button className="connection-group-head" onClick={onToggle}>
        <span className={`group-chevron ${expanded ? 'open' : ''}`}>›</span>
        <span className="group-main">
          <b>{group.process}</b>
          <small>PID {group.pid || '未知'} · {group.ips.length} 个外联 IP · {group.connections.length} 条连接</small>
        </span>
        <span className="group-ip-preview" title={group.ips.join(', ')}>{previewIps}{hiddenCount ? ` 等 ${hiddenCount} 个` : ''}</span>
        <span className={`risk-badge ${group.risk}`}>{severityLabel[group.risk] || group.risk}</span>
      </button>
      <div className="connection-group-meta">
        <span title={group.path || ''}>{group.path || '无 EXE 路径'}</span>
        <small>{(group.reasons || []).join('；') || '同一 PID 外联连接已聚合，点击展开查看全部 IP'}</small>
      </div>
      {group.ips.length > 0 && (
        <div className="conn-intel-bar">
          <button type="button" className="text-link intel-btn" title="在系统浏览器打开 VirusTotal / 微步在线查询这些外联 IP 的威胁情报" onClick={() => openThreatIntel('ip', group.ips[0])}>
            🔍 查情报：{group.ips[0]}{group.ips.length > 1 ? ` 等 ${group.ips.length} 个` : ''}
          </button>
        </div>
      )}
      {expanded && (
        <div className="connection-group-body">
          {group.connections.map((c) => <ConnectionRow compact key={`${c.remoteAddress}-${c.remotePort}-${c.pid}-${c.localPort}`} c={c} openPathTarget={openPathTarget} />)}
        </div>
      )}
    </article>
  )
}

function ConnectionRow({ c, compact = false, openPathTarget }) {
  const targetPath = c.path || c.commandLine || ''
  return (
    <article className={`connection-row severity-${c.risk} ${compact ? 'compact' : ''}`} title={targetPath ? '右键打开进程所在目录' : ''} onContextMenu={(e) => { if (targetPath) openPathTarget?.(targetPath, e) }}>
      <div className="conn-proc"><b>{c.process || '未知进程'}</b><span title={c.path || ''}>{c.path || '无 EXE 路径'}</span><em title={c.commandLine || ''}>{c.commandLine || '无命令行'}</em></div>
      <div className="conn-remote"><b>{c.external ? `${c.remoteAddress}:${c.remotePort}` : `${c.localAddress}:${c.localPort}`}</b><span>{c.state} · PID {c.pid}</span></div>
      <div className="conn-risk"><span className={`risk-badge ${c.risk}`}>{severityLabel[c.risk] || c.risk}</span><small>{(c.reasons || []).join('；') || (targetPath ? '右键打开所在目录' : '')}</small></div>
    </article>
  )
}

// IOC 威胁情报跳转：点外联 IP / DNS 域名 / 文件哈希，在系统默认浏览器打开 VirusTotal / 微步在线查询页
const THREAT_INTEL_SOURCES = {
  vt: { name: 'VirusTotal', ip: 'https://www.virustotal.com/gui/ip-address/', domain: 'https://www.virustotal.com/gui/domain/', hash: 'https://www.virustotal.com/gui/file/', url: 'https://www.virustotal.com/gui/url/' },
  tb: { name: '微步在线', ip: 'https://x.threatbook.com/v5/ip/', domain: 'https://x.threatbook.com/v5/domain/', hash: 'https://x.threatbook.com/v5/file/', url: 'https://x.threatbook.com/v5/url/' },
}
function openThreatIntel(type, value) {
  if (!value) return
  const v = String(value).trim()
  const choice = window.prompt(
    `查询威胁情报：${type} = ${v}\n\n请选择查询源（输入对应数字）：\n1 = VirusTotal\n2 = 微步在线\n3 = 两个都打开\n（留空或取消则不查询）`,
    '1'
  )
  if (choice === null || choice === '') return
  const key = type === 'url' ? 'url' : type
  const open = (srcKey) => {
    const url = THREAT_INTEL_SOURCES[srcKey]?.[key] + encodeURIComponent(v)
    window.open(url, '_blank', 'noopener')
  }
  if (choice === '1') open('vt')
  else if (choice === '2') open('tb')
  else if (choice === '3') { open('vt'); open('tb') }
}

function sortProcessRows(rows, sort) {
  const key = sort?.key || 'risk'
  const dir = sort?.dir === 'asc' ? 1 : -1
  return [...(rows || [])].sort((a, b) => {
    const av = processSortValue(a, key)
    const bv = processSortValue(b, key)
    if (typeof av === 'number' && typeof bv === 'number') {
      return (av - bv) * dir
    }
    return String(av || '').localeCompare(String(bv || ''), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' }) * dir
  })
}

function processSortValue(row, key) {
  if (key === 'risk') return severityWeight(row?.risk)
  if (key === 'pid' || key === 'ppid') return Number(row?.[key] || 0)
  if (key === 'cpu' || key === 'memoryMB') return Number(row?.[key] || 0)
  if (key === 'creationDate') {
    const t = new Date(row?.creationDate || 0).getTime()
    return Number.isFinite(t) ? t : 0
  }
  if (key === 'path') return processDisplayPath(row).toLowerCase()
  return String(row?.[key] || '').toLowerCase()
}

function processDisplayPath(proc) {
  const direct = String(proc?.path || '').trim()
  if (direct) return direct
  const parsed = extractExecutableFromCommandLine(proc?.commandLine)
  return parsed || '无路径'
}

function extractExecutableFromCommandLine(commandLine) {
  const text = String(commandLine || '').trim()
  if (!text) return ''
  const quoted = text.match(/"([^"]+\.(?:exe|dll|ps1|vbs|js|bat|cmd))"/i)
  if (quoted?.[1]) return quoted[1].trim()
  const unquoted = text.match(/[A-Za-z]:\\[^\s"]+\.(?:exe|dll|ps1|vbs|js|bat|cmd)/i)
  if (unquoted?.[0]) return unquoted[0].trim()
  return ''
}

function ConfigRow({ title, value, risk, reasons, onIntel }) {
  return (
    <article className={`config-row severity-${risk}`}>
      <div><b>{title}</b><span>{value}</span>{onIntel && <button type="button" className="text-link intel-inline" title="查询威胁情报" onClick={onIntel}>🔍 查情报</button>}</div>
      <div><span className={`risk-badge ${risk}`}>{severityLabel[risk] || risk}</span><small>{(reasons || []).join('；')}</small></div>
    </article>
  )
}

function PersistencePanel({ data, loading, refresh, deleteTask, deleteService, deleteAutorun, deleteWmi, deleteStartupFile, deleteBusy, openPathTarget, onOpenResponse }) {
  const [activeTab, setActiveTab] = useState('autoruns')
  const [filter, setFilter] = useState('')
  const autoruns = sortRowsByRisk(data?.autoruns || [])
  const startupFiles = sortRowsByRisk(data?.startupFiles || [])
  const tasks = sortRowsByRisk(data?.tasks || [])
  const services = sortRowsByRisk(data?.services || [])
  const wmi = sortRowsByRisk(data?.wmi || [])
  const riskyAutoruns = autoruns.filter((x) => x.risk !== 'low').length
  const riskyTasks = tasks.filter((x) => x.risk !== 'low').length
  const riskyServices = services.filter((x) => x.risk !== 'low').length
  const tabItems = [
    { id: 'autoruns', name: '注册表启动项', count: autoruns.length },
    { id: 'tasks', name: '计划任务', count: tasks.length },
    { id: 'services', name: '系统服务', count: services.length },
    { id: 'wmi', name: 'WMI订阅', count: wmi.length },
    { id: 'startupFiles', name: '启动目录', count: startupFiles.length },
  ]
  const sourceRows = { autoruns, tasks, services, wmi, startupFiles }[activeTab] || []
  const rows = flatFilterRows(sourceRows, filter, (row) => JSON.stringify(row))
  const activeName = tabItems.find((x) => x.id === activeTab)?.name || '持久化'
  return (
    <div className="card data-card persistence-tabs-card">
      <FlatTabs tabs={tabItems} active={activeTab} onChange={setActiveTab} />
      <FlatToolbar loading={loading} onRefresh={refresh} filter={filter} onFilter={setFilter} placeholder={activeTab === 'tasks' ? '任务名 / 执行命令' : '名称 / 路径 / 命令行'} visible={rows.length} total={sourceRows.length} summary={`${activeName} · 注册表风险 ${riskyAutoruns} 项 · 任务风险 ${riskyTasks} 项 · 服务风险 ${riskyServices} 项`} onOpenResponse={onOpenResponse} />

      <div className="summary-metrics">
        <div className={`summary-metric ${riskyAutoruns ? 'danger' : 'ok'}`}><small>注册表启动项</small><b>{autoruns.length}</b><span>风险 {riskyAutoruns}</span></div>
        <div className={`summary-metric ${riskyTasks ? 'danger' : 'ok'}`}><small>计划任务</small><b>{tasks.length}</b><span>风险 {riskyTasks}</span></div>
        <div className={`summary-metric ${riskyServices ? 'danger' : 'ok'}`}><small>服务 / WMI</small><b>{services.length}/{wmi.length}</b><span>服务风险 {riskyServices}</span></div>
      </div>

      <div className="detail-list">
        {activeTab === 'autoruns' && (
          <section className="detail-section">
            <div className="detail-title"><b>注册表启动项</b><span>{rows.length} 项</span></div>
            {rows.map((a) => <PersistenceRow key={`${a.location}-${a.name}`} title={a.name} meta={`${a.description || '无描述'} · 公司 ${a.companyName || '未知公司'} · ${a.source || pathSourceLabel(a.location)} · ${a.enabled === false ? '已禁用' : '已启用'} · 签名 ${a.signatureStatus || '未知'} · 命令行 ${a.command || '无'}`} command={a.command} path={a.path} risk={a.risk} reasons={a.reasons} openPathTarget={openPathTarget} actionLabel="删除" onDelete={deleteAutorun ? () => deleteAutorun(a) : null} deleting={deleteBusy === `autorun::${a.name}@${a.location}`} />)}
            {!rows.length && <div className="empty-state">{loading ? '正在读取注册表启动项...' : '未读取到注册表启动项'}</div>}
          </section>
        )}

        {activeTab === 'tasks' && (
          <section className="detail-section">
            <div className="detail-title"><b>计划任务</b><span>{rows.length} 项</span></div>
            {rows.map((t) => <PersistenceRow key={`${t.taskPath}-${t.taskName}`} title={`${t.taskPath || ''}${t.taskName || ''}`} meta={`${t.enabled === false || t.state === 'Disabled' ? '已禁用' : '已启用'} · ${t.state || 'Unknown'} · ${t.author || 'Unknown Author'} · 上次 ${fmtDate(t.lastRunTime)} · 下次 ${fmtDate(t.nextRunTime)}`} command={`${t.execute || ''} ${t.arguments || ''}`.trim()} path={t.execute} risk={t.risk} reasons={t.description ? [...(t.reasons || []), t.description] : t.reasons} openPathTarget={openPathTarget} actionLabel="删除" onDelete={deleteTask ? () => deleteTask(t) : null} deleting={deleteBusy === `task::${t.taskPath || ''}${t.taskName || ''}`} />)}
            {!rows.length && <div className="empty-state">{loading ? '正在读取计划任务...' : '未读取到计划任务'}</div>}
          </section>
        )}

        {activeTab === 'services' && (
          <section className="detail-section">
            <div className="detail-title"><b>系统服务</b><span>{rows.length} 项</span></div>
            {rows.map((s) => <PersistenceRow key={s.name} title={`${s.displayName || s.name} (${s.name})`} meta={`${s.state || 'Unknown'} · ${s.startMode || 'Unknown'} · ${s.startName || 'Unknown'} · ${s.companyName || '未知厂商'} · 签名 ${s.signatureStatus || '未知'}`} command={s.pathName} path={s.executablePath || s.pathName} risk={s.risk} reasons={s.reasons} openPathTarget={openPathTarget} actionLabel="删除" onDelete={deleteService ? () => deleteService(s) : null} deleting={deleteBusy === `svc::${s.name}`} />)}
            {!rows.length && <div className="empty-state">{loading ? '正在读取系统服务...' : '未读取到系统服务'}</div>}
          </section>
        )}

        {activeTab === 'wmi' && (
          <section className="detail-section">
            <div className="detail-title"><b>WMI 永久订阅</b><span>{rows.length} 项</span></div>
            {rows.map((w) => <PersistenceRow key={`${w.kind}-${w.name}`} title={`${w.kind}: ${w.name}`} meta={w.query || 'WMI Consumer'} command={w.command || w.query} path={w.command} risk={w.risk} reasons={w.reasons} openPathTarget={openPathTarget} actionLabel="删除" onDelete={deleteWmi ? () => deleteWmi(w) : null} deleting={deleteBusy === `wmi::${w.kind}-${w.name}`} />)}
            {!rows.length && <div className="empty-state">{loading ? '正在读取 WMI 订阅...' : '未发现 WMI 永久订阅'}</div>}
          </section>
        )}

        {activeTab === 'startupFiles' && (
          <section className="detail-section">
            <div className="detail-title"><b>启动目录文件</b><span>{rows.length} 个文件</span></div>
            {rows.map((f) => <PersistenceRow key={f.fullName} title={f.fullName} meta={`创建 ${fmtDate(f.creationTime)} · 修改 ${fmtDate(f.lastWriteTime)} · ${fmtBytes(f.length)}`} command={f.fullName} path={f.fullName} risk={f.risk} reasons={f.reasons} openPathTarget={openPathTarget} actionLabel="删除" onDelete={deleteStartupFile ? () => deleteStartupFile(f) : null} deleting={deleteBusy === `startup::${f.fullName}`} />)}
            {!rows.length && <div className="empty-state">{loading ? '正在读取启动目录文件...' : '未读取到启动目录文件'}</div>}
          </section>
        )}
      </div>
    </div>
  )
}

function PersistenceRow({ title, meta, command, path, risk, reasons, openPathTarget, actionLabel, onDelete, deleting }) {
  const targetPath = path || command || ''
  return (
    <article className={`persistence-row severity-${risk}`} title={targetPath ? '右键选择打开所在目录' : ''} onContextMenu={(e) => { if (targetPath) openPathTarget?.(targetPath, e) }}>
      <div className="persist-main"><b title={title}>{title || '未知项'}</b><span title={meta}>{meta || '无补充信息'}</span></div>
      <div className="persist-command"><b title={path || command}>{path || '未解析到路径'}</b><span title={command}>{command || '无命令'}</span></div>
      <div className="persist-risk"><span className={`risk-badge ${risk}`}>{severityLabel[risk] || risk}</span><small>{(reasons || []).filter(Boolean).join('；') || (targetPath ? '右键选择打开所在目录' : '')}</small></div>
      {onDelete && (
        <div className="persist-action">
          <button className="kill force persist-delete" type="button" disabled={deleting} onClick={(e) => { e.stopPropagation(); onDelete() }}>
            {deleting ? '处理中…' : (actionLabel || '删除')}
          </button>
        </div>
      )}
    </article>
  )
}

function FilesPanel({ options, onOpenResponse, openPathTarget }) {
  const [activeTab, setActiveTab] = useState('tempFiles')
  const [filter, setFilter] = useState('')
  const [fileInfo, setFileInfo] = useState(null)
  const [loading, setLoading] = useState(false)

  async function refreshFiles() {
    setLoading(true)
    try {
      const data = await api(`/api/files?days=${Number(options?.lookbackDays) || 7}`)
      setFileInfo(data)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refreshFiles() }, [options?.lookbackDays])

  const tempFiles = sortRowsByRisk(fileInfo?.tempFiles || [])
  const downloadFiles = sortRowsByRisk(fileInfo?.downloadFiles || [])
  const recentExecutables = sortRowsByRisk(fileInfo?.recentExecutables || [])
  const prefetchFiles = sortRowsByRisk(fileInfo?.prefetchFiles || [])
  const ads = sortRowsByRisk(fileInfo?.ads || [])
  const webLogs = sortRowsByRisk(fileInfo?.webLogs || [])
  const tabItems = [
    { id: 'tempFiles', name: '临时目录', count: tempFiles.length },
    { id: 'downloadFiles', name: '下载目录', count: downloadFiles.length },
    { id: 'recentExecutables', name: '近期可执行文件', count: recentExecutables.length },
    { id: 'prefetchFiles', name: 'Prefetch', count: prefetchFiles.length },
    { id: 'ads', name: 'ADS备用数据流', count: ads.length },
    { id: 'webLogs', name: 'Web日志', count: webLogs.length },
  ]
  const sourceRows = { tempFiles, downloadFiles, recentExecutables, prefetchFiles, ads, webLogs }[activeTab] || []
  const rows = flatFilterRows(sourceRows, filter, (row) => JSON.stringify(row))
  const total = tempFiles.length + downloadFiles.length + recentExecutables.length + prefetchFiles.length + ads.length + webLogs.length
  const activeName = tabItems.find((x) => x.id === activeTab)?.name || '文件取证'
  const riskyFiles = [...tempFiles, ...downloadFiles, ...recentExecutables, ...prefetchFiles, ...ads, ...webLogs].filter((x) => x.risk !== 'low').length
  const hintMap = {
    tempFiles: '排查 TEMP / Windows Temp 中近期新增、脚本、压缩包和可执行文件。',
    downloadFiles: '排查用户 Downloads 目录中的近期下载、脚本和可执行文件。',
    recentExecutables: '重点关注 exe/dll/ps1/vbs/js/bat/cmd 等近期落地文件。',
    prefetchFiles: 'Prefetch 可辅助还原程序执行痕迹和首次运行时间。',
    ads: '检查 NTFS ADS 备用数据流，识别隐藏载荷或异常流。',
    webLogs: 'Web 日志聚合 POST/GET/WebShell 关键字命中记录。',
  }
  return (
    <div className="card data-card files-tabs-card">
      <FlatTabs tabs={tabItems} active={activeTab} onChange={setActiveTab} />
      <FlatToolbar loading={loading} onRefresh={refreshFiles} filter={filter} onFilter={setFilter} placeholder="路径 / 文件名过滤" visible={rows.length} total={sourceRows.length} summary={`${activeName} · 总计 ${total} 项 · 风险 ${riskyFiles} 项 · 回溯 ${Number(options?.lookbackDays) || 7} 天`} onOpenResponse={onOpenResponse} />
      <div className="summary-metrics">
        <div className={`summary-metric ${recentExecutables.length ? 'warn' : 'ok'}`}><small>可执行/脚本</small><b>{recentExecutables.length}</b><span>近期落地风险文件</span></div>
        <div className={`summary-metric ${prefetchFiles.length ? 'info' : 'ok'}`}><small>Prefetch</small><b>{prefetchFiles.length}</b><span>执行痕迹</span></div>
        <div className={`summary-metric ${ads.length || webLogs.length ? 'warn' : 'ok'}`}><small>ADS/Web 命中</small><b>{ads.length}/{webLogs.length}</b><span>隐藏流 / 日志命中</span></div>
      </div>
      <div className="detail-list">
        <FileEvidenceSection title={activeName} hint={hintMap[activeTab]} rows={rows} loading={loading} openPathTarget={openPathTarget} />
      </div>
    </div>
  )
}

function FileEvidenceSection({ title, hint, rows, loading, openPathTarget }) {
  return (
    <section className="detail-section">
      <div className="detail-title"><b>{title}</b><span>{rows.length} ?</span></div>
      <small className="section-hint">{hint}</small>
      <div className="file-evidence-list">
        {rows.map((row, idx) => <FileEvidenceRow key={`${title}-${idx}-${row.path || row.fullName || row.line || row.stream}`} row={row} openPathTarget={openPathTarget} />)}
      </div>
      {!rows.length && <div className="empty-state">{loading ? '正在读取文件取证结果...' : '当前分类暂无结果'}</div>}
    </section>
  )
}

function FileEvidenceRow({ row, openPathTarget }) {
  const targetPath = row.path || row.fullName || row.text || ''
  const title = row.path || row.fullName || row.name || row.line || '未知文件'
  const meta = row.line || row.stream || [fmtBytes(row.length), fmtDate(row.creationTime), fmtDate(row.lastWriteTime)].filter((x) => x && x !== '未知').join(' · ') || row.text || ''
  return (
    <article className={`file-row severity-${row.risk || 'low'}`} title={targetPath ? '右键选择打开所在目录' : ''} onContextMenu={(e) => { if (targetPath && openPathTarget) openPathTarget(targetPath, e) }}>
      <b title={title}>{title}</b>
      <span title={meta}>{meta}</span>
      <em><span className={`risk-badge ${row.risk || 'low'}`}>{severityLabel[row.risk] || row.risk || '未知'}</span></em>
    </article>
  )
}

function ModuleEvidencePanel({ active, scan, onOpenResponse }) {
  const results = moduleResults(active, scan)
  const summary = buildModuleSummary(active, scan)
  const titleMap = { host: '主机采集结果', network: '网络采集结果', persistence: '持久化采集结果', files: '文件取证结果', tools: '工具运行状态', settings: '采集参数与输出' }
  return (
    <div className="card data-card">
      <div className="card-head">
        <div><h2>{titleMap[active] || '模块采集结果'} <span className="count-pill">{results.length}</span></h2><small>{summary.subtitle}</small></div>
        <button className="text-link" onClick={onOpenResponse}>完整响应</button>
      </div>
      <div className="summary-metrics">
        {summary.metrics.map((m) => <div className={`summary-metric ${m.tone || ''}`} key={m.label}><small>{m.label}</small><b>{m.value}</b><span>{m.hint}</span></div>)}
      </div>
      <div className="evidence-list structured">
        {summary.sections.map((s) => (
          <article className={`summary-section ${s.tone || ''}`} key={s.title}>
            <div className="summary-section-head"><b>{s.title}</b><span>{s.status}</span></div>
            <ul>{s.lines.map((line) => <li key={line}>{line}</li>)}</ul>
            <em>{s.advice}</em>
          </article>
        ))}
        {!results.length && <div className="empty-state">暂无该模块采集结果，点击“启动排查”后会显示。</div>}
      </div>
    </div>
  )
}

function LogPanel({ title, lines }) {
  return (
    <div className="card log-card">
      <div className="card-head"><h2>{title} <span className="count-pill">{lines.length}</span></h2><button className="text-link" onClick={() => copyToClipboard(lines.map((l) => l.text).join('\n'))}>复制</button></div>
      <div className="log-stream">{lines.map((line, idx) => <div key={idx} className={`log-line ${line.type || ''}`}><time>{line.time}</time><span>{line.text}</span></div>)}</div>
    </div>
  )
}

function AnomalyPanel({ items, scan, onNavigate, onOpenResponse, title = '异常发现与清除建议', emptyText = '建议先执行“智能排查”，再重点复核外联连接、临时目录执行、账号变更、服务安装、WMI 持久化和日志清理事件。' }) {
  const criticalCount = items.filter((x) => ['critical', 'high'].includes(x.severity)).length
  return (
    <div className="card anomaly-card">
      <div className="card-head anomaly-head">
        <div>
          <h2>{title} <span className="count-pill">{items.length}</span></h2>
          <small>{scan?.status === 'running' ? '采集中，发现会持续刷新' : criticalCount ? `优先处置 ${criticalCount} 个严重/高危项` : '未命中高危规则，仍需结合业务基线复核'}</small>
        </div>
        <button className="text-link full-response-link" onClick={onOpenResponse}>查看完整响应</button>
      </div>
      <div className="anomaly-list">
        {items.slice(0, 12).map((item) => <AnomalyItem key={item.id} item={item} onNavigate={onNavigate} />)}
        {!items.length && (
          <div className="safe-state">
            <b>当前未发现明确异常</b>
            <span>{emptyText}</span>
            <button className="secondary" onClick={() => onNavigate('report')}>查看报告中心</button>
          </div>
        )}
      </div>
    </div>
  )
}

function AnomalyItem({ item, onNavigate }) {
  return (
    <article className={`anomaly-item severity-${item.severity}`}>
      <div className="anomaly-top">
        <span className={`risk-badge ${item.severity}`}>{severityLabel[item.severity] || item.severity}</span>
        <small>{item.category} · {item.source}</small>
      </div>
      <h3>{item.title}</h3>
      <p>{item.evidence}</p>
      <div className="cleanup-box">
        <b>清除/处置：</b>
        <span>{item.remediation}</span>
      </div>
      <div className="anomaly-actions">
        {item.nav && <button className="secondary compact" onClick={() => onNavigate(item.nav)}>{item.actionLabel || '查看处置入口'}</button>}
        <button className="text-link" onClick={() => copyToClipboard(`${item.title}\n${item.evidence}\n处置：${item.remediation}`)}>复制证据</button>
      </div>
    </article>
  )
}

function FullResponseModal({ scan, status, processes, hostInfo, accounts, events, networkInfo, persistenceInfo, anomalies, logLines, onClose }) {
  const [filter, setFilter] = useState('')
  const [copied, setCopied] = useState(false)
  const fullText = useMemo(
    () => formatFullResponseText({ scan, status, processes, hostInfo, accounts, events, networkInfo, persistenceInfo, anomalies, logLines }),
    [scan, status, processes, hostInfo, accounts, events, networkInfo, persistenceInfo, anomalies, logLines]
  )
  const displayText = useMemo(() => filterFullResponse(fullText, filter), [fullText, filter])

  async function copyText() {
    await copyToClipboard(displayText)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  return (
    <div className="response-modal" role="dialog" aria-modal="true">
      <div className="response-box">
        <div className="response-head">
          <div><h2>完整响应</h2><p>包含异常研判、进程摘要、扫描发现、执行日志与处置建议</p></div>
          <div className="response-actions"><button className="secondary compact" onClick={copyText}>{copied ? '已复制' : '复制'}</button><button className="close" onClick={onClose}>关闭</button></div>
        </div>
        <div className="response-filters">
          <button className="chip-btn" onClick={() => setFilter('')}>全部</button>
          <button className="chip-btn" onClick={() => setFilter('异常|高危|严重|可疑')}>异常</button>
          <button className="chip-btn" onClick={() => setFilter('系统版本|Build|补丁|主机')}>主机</button>
          <button className="chip-btn" onClick={() => setFilter('进程|PID|CommandLine')}>进程</button>
          <button className="chip-btn" onClick={() => setFilter('网络|ESTABLISHED|外联|LISTEN')}>网络</button>
          <button className="chip-btn" onClick={() => setFilter('注册表|Run|RunOnce|计划任务|服务|WMI')}>持久化</button>
          <button className="chip-btn" onClick={() => setFilter('\\bPOST\\b')}>POST 请求</button>
          <button className="chip-btn" onClick={() => setFilter('\\bGET\\b')}>GET 请求</button>
          <input value={filter} placeholder="自定义关键词或正则，例如 4625|powershell" onChange={(e) => setFilter(e.target.value)} />
        </div>
        <pre className="response-log">{displayText || '无匹配内容'}</pre>
      </div>
    </div>
  )
}

function FindingCard({ finding }) {
  return <article className={`finding-card severity-${finding.severity}`}><div><span className={`risk-badge ${finding.severity}`}>{severityLabel[finding.severity] || finding.severity}</span><small>{finding.ruleId} · {finding.sourceTaskId}</small></div><h3>{finding.title}</h3><p>{finding.recommendation}</p><pre>{finding.evidence}</pre></article>
}

function Advice({ title, text }) {
  return <div className="advice"><b>{title}</b><span>{text}</span></div>
}

function Metric({ icon, label, value, tone = '' }) {
  return <div className={`metric ${tone}`}><span>{icon}</span><small>{label}</small><b>{value}</b></div>
}

function Notice({ type, text }) {
  return <div className={`notice ${type}`}>{text}</div>
}

function TaskDrawer({ data, scan, notes, onClose }) {
  const { task, result } = data
  return <div className="drawer"><div className="drawer-box"><button className="close" onClick={onClose}>关闭</button><h2>{task.title}</h2><p className="muted">{task.category} · {task.skill} · {result?.status || 'pending'}</p><p>{notes || task.notes}</p>{result?.preview ? <pre>{result.preview}</pre> : <p className="empty-state">任务尚未完成。</p>}{scan?.id && result && <a className="primary link" href={`/api/scans/${scan.id}/raw/${task.id}`} target="_blank" rel="noreferrer">打开完整原始输出</a>}</div></div>
}

function countSeverities(findings) {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})
}

function moduleResults(active, scan) {
  const ids = {
    host: ['basic', 'users', 'processes', 'network', 'files'],
    network: ['network'],
    persistence: ['autoruns', 'tasks', 'services', 'wmi', 'system-events'],
    logs: ['security-events', 'system-events', 'powershell-events', 'web-logs'],
    accounts: ['users', 'security-events'],
    files: ['files', 'web-logs'],
    tools: ['basic', 'defender'],
    settings: ['basic'],
  }[active] || []
  return (scan?.results || []).filter((r) => ids.includes(r.taskId))
}

function buildModuleSummary(active, scan) {
  const results = moduleResults(active, scan)
  const result = (id) => results.find((r) => r.taskId === id)
  const statusOf = (id) => {
    const r = result(id)
    if (!r) return '未采集'
    if (r.status === 'ok') return '已检查'
    if (r.status === 'timeout') return '超时'
    return '异常'
  }
  const okCount = results.filter((r) => r.status === 'ok').length
  const badCount = results.filter((r) => r.status !== 'ok').length
  const findingCount = (scan?.findings || []).filter((f) => moduleFindingMatch(active, f)).length
  const basic = cleanText(result('basic')?.preview || '')
  const host = pickAfter(basic, '=== Host ===') || '未知'
  const user = pickAfter(basic, '=== Current User ===') || '未知'

  const base = {
    subtitle: `已完成 ${okCount}/${results.length || 0} 个采集任务，异常任务 ${badCount} 个`,
    metrics: [
      { label: '采集任务', value: `${okCount}/${results.length || 0}`, hint: '模块命令完成度', tone: badCount ? 'warn' : 'ok' },
      { label: '风险命中', value: findingCount, hint: '该模块关联规则', tone: findingCount ? 'danger' : 'ok' },
      { label: '报告状态', value: scan?.status || 'ready', hint: scan?.reportPath ? '已生成 HTML' : '等待生成', tone: scan?.status === 'completed' ? 'ok' : '' },
    ],
    sections: [],
  }

  if (active === 'host') {
    base.metrics[1] = { label: '主机', value: host, hint: user, tone: 'info' }
    base.sections = [
      { title: '基础信息与权限', status: statusOf('basic'), tone: statusTone(result('basic')), lines: [`主机名：${host}`, `当前用户：${user}`, '已采集 whoami /groups /priv、系统版本、补丁和 IP 配置。'], advice: '确认当前权限是否满足应急排查；普通权限下建议以管理员重新运行。' },
      { title: '账号与会话', status: statusOf('users'), tone: statusTone(result('users')), lines: ['已采集 query user、query session、net user、管理员组和本地用户。', '账号详情建议切换到“账号审计”页面查看结构化列表。'], advice: '重点核对管理员组、隐藏账号和异常登录时间。' },
      { title: '进程与网络', status: `${statusOf('processes')} / ${statusOf('network')}`, tone: statusTone(result('processes')) || statusTone(result('network')), lines: ['已采集进程命令行、启动时间、网络连接、DNS、路由和代理。', '可疑进程可在“进程清除”页面直接处置。'], advice: '外联和可疑进程需要关联 PID、路径、命令行和父子进程链。' },
      { title: '文件取证', status: statusOf('files'), tone: statusTone(result('files')), lines: ['已采集临时目录、下载目录、近期可执行文件、Prefetch 和 ADS。'], advice: '对临时目录落地样本先复制取证和计算哈希，再清除。' },
    ]
    return base
  }

  if (active === 'network') {
    const text = cleanText(result('network')?.preview || '')
    base.sections = [
      { title: '外联连接与监听端口', status: statusOf('network'), tone: statusTone(result('network')), lines: [`ESTABLISHED 采样：${countMatches(text, /ESTABLISHED|Established/g)} 条`, `监听采样：${countMatches(text, /LISTENING|Listen/g)} 条`, '已关联 PID 和进程名。'], advice: '外联 IP 需结合业务白名单和威胁情报判断，确认异常后阻断并定位进程。' },
      { title: 'DNS 缓存与 DNS 服务器', status: statusOf('network'), tone: statusTone(result('network')), lines: ['已执行 ipconfig /displaydns、Get-DnsClientCache、Get-DnsClientServerAddress。', '完整 DNS 明细可在完整响应或 HTML 报告中筛选 DNS。'], advice: '关注异常动态域名、DNSLog、隧道域名和非授权 DNS 服务器。' },
      { title: '路由表、持久路由与代理', status: statusOf('network'), tone: statusTone(result('network')), lines: ['已执行 route print、Get-NetRoute、持久路由注册表、WinHTTP/HKCU 代理检查。'], advice: '未知代理或持久路由可能导致流量劫持或绕行，需要导出后恢复基线。' },
    ]
    return base
  }

  if (active === 'persistence') {
    base.sections = [
      { title: '注册表启动项与启动文件夹', status: statusOf('autoruns'), tone: statusTone(result('autoruns')), lines: ['已检查 HKLM/HKCU Run、RunOnce、WOW6432Node、Winlogon 和 Startup 文件夹。'], advice: '临时目录、用户目录、脚本宿主启动项优先核验。' },
      { title: '计划任务', status: statusOf('tasks'), tone: statusTone(result('tasks')), lines: ['已采集 schtasks /query /fo LIST /v 与 Get-ScheduledTask。'], advice: '关注 powershell、cmd、mshta、rundll32、certutil、bitsadmin 等执行链。' },
      { title: '服务、驱动与 WMI', status: `${statusOf('services')} / ${statusOf('wmi')}`, tone: statusTone(result('services')) || statusTone(result('wmi')), lines: ['已采集 Win32_Service、Win32_SystemDriver、WMI EventFilter/Consumer/Binding。'], advice: '新服务、未加引号路径、WMI 永久订阅需先导出再禁用/删除。' },
    ]
    return base
  }

  if (active === 'files') {
    base.sections = [
      { title: '临时目录与下载目录', status: statusOf('files'), tone: statusTone(result('files')), lines: ['已按时间倒序采集 TEMP、Windows Temp、Downloads。'], advice: '近期新增脚本/可执行文件需关联进程、Prefetch 和日志时间线。' },
      { title: 'Prefetch 执行痕迹', status: statusOf('files'), tone: statusTone(result('files')), lines: ['已采集 Windows Prefetch 最近执行记录。'], advice: 'Prefetch 可证明程序运行过，即使样本已被删除。' },
      { title: 'ADS 与 Web 日志', status: `${statusOf('files')} / ${statusOf('web-logs')}`, tone: statusTone(result('files')) || statusTone(result('web-logs')), lines: ['已执行 dir /r 检查备用数据流，并采样 IIS/HTTP 日志。'], advice: 'ADS 可隐藏载荷；WebShell 请求需关联文件落地时间。' },
    ]
    return base
  }

  if (active === 'tools') {
    base.sections = [
      { title: '后端与运行环境', status: statusOf('basic'), tone: statusTone(result('basic')), lines: ['后端 API、React 前端和 WebView2 桌面窗口已集成。'], advice: '如接口离线，重启 EXE 或检查端口占用。' },
      { title: 'Defender 与防火墙', status: statusOf('defender'), tone: statusTone(result('defender')), lines: ['已检查 Defender 实时防护、排除项、防火墙配置和 hosts 文件。'], advice: '非授权排除项和关闭防护需要追踪策略变更来源。' },
    ]
    return base
  }

  base.sections = [
    { title: '采集配置', status: scan?.status || 'ready', tone: scan?.status === 'completed' ? 'ok' : 'info', lines: [`Profile：${scan?.options?.profile || 'combined'}`, `回溯范围：${lookbackLabel(scan?.options?.lookbackDays ?? defaultOptions.lookbackDays)}`, `事件上限：${scan?.options?.maxEvents || 800}`, `输出目录：${scan?.outputDir || '未生成'}`], advice: '修改配置后重新启动排查即可生成新的证据目录。' },
  ]
  return base
}

function moduleFindingMatch(active, finding) {
  const text = `${finding.category || ''} ${finding.sourceTaskId || ''} ${finding.ruleId || ''} ${finding.title || ''}`.toLowerCase()
  const keys = {
    host: ['basic', 'users', 'processes', 'network', 'files', '账户', '进程', '网络', '文件'],
    network: ['network', '网络', 'dns', 'route', 'proxy'],
    persistence: ['autoruns', 'tasks', 'services', 'wmi', 'persistence', '持久化', '服务'],
    files: ['files', 'file', 'web', '文件', '临时'],
    tools: ['defender', 'collector', '防护'],
    settings: ['collector'],
  }[active] || []
  return keys.some((k) => text.includes(k))
}

function statusTone(result) {
  if (!result) return 'info'
  if (result.status === 'ok') return 'ok'
  if (result.status === 'timeout') return 'warn'
  return 'danger'
}

function pickAfter(text, marker) {
  const idx = text.indexOf(marker)
  if (idx < 0) return ''
  const rest = text.slice(idx + marker.length).split(/\r?\n/).map((x) => x.trim()).filter(Boolean)
  return rest[0] || ''
}

function countMatches(text, re) {
  return (text.match(re) || []).length
}

function buildLogLines(scan, processes, status) {
  const now = new Date().toLocaleTimeString()
  const lines = [{ time: now, type: 'info', text: `[SYSTEM] ${status?.hostname || 'localhost'} 应急客户端就绪，等待指令` }]
  if (processes.length) {
    const risky = processes.filter((p) => ['high', 'medium'].includes(p.risk)).length
    lines.push({ time: now, type: risky ? 'warn' : 'success', text: `[PROCESS] 已载入 ${processes.length} 个进程，可疑进程 ${risky} 个` })
  }
  if (scan?.tasks?.length) {
    lines.push({ time: fmtTime(scan.startedAt), type: 'info', text: `[SCAN] ${scan.id} ${scan.status} profile=${scan.options?.profile} tasks=${scan.tasks.length}` })
    ;(scan.results || []).slice(-12).forEach((r) => lines.push({ time: fmtTime(r.finishedAt), type: r.status === 'ok' ? 'success' : 'warn', text: `[${r.taskId}] ${r.title} ${r.status} ${r.durationMs}ms` }))
    ;(scan.findings || []).slice(0, 10).forEach((f) => lines.push({ time: fmtTime(f.createdAt), type: ['critical', 'high'].includes(f.severity) ? 'danger' : 'warn', text: `[${f.severity}] ${f.title} === ${f.evidence}` }))
  }
  return lines
}

function buildNetworkFallbackFromScan(scan, processes = []) {
  const procMap = new Map((processes || []).map((p) => [String(p.pid), p]))
  const rows = []
  const seen = new Set()
  ;(scan?.findings || [])
    .filter((f) => {
      const text = `${f.ruleId || ''} ${f.category || ''} ${f.title || ''} ${f.evidence || ''}`.toLowerCase()
      return text.includes('win.external_established') || text.includes('外部 established') || text.includes('外联') || (text.includes('established') && text.includes('tcp'))
    })
    .forEach((f) => {
      parseExternalConnectionsFromEvidence(f.evidence || '').forEach((c) => {
        const key = connectionKey(c)
        if (seen.has(key)) return
        seen.add(key)
        const proc = procMap.get(String(c.pid))
        const processRisk = proc && ['critical', 'high', 'medium'].includes(proc.risk) ? proc.risk : 'medium'
        const reasons = ['扫描结果发现外部 ESTABLISHED 连接']
        const exePath = proc?.path || c.path || ''
        if (exePath) {
          reasons.push(`PID ${c.pid} 已关联 EXE：${exePath}`)
        } else {
          reasons.push(`PID ${c.pid} 当前未读取到 EXE 路径，可能需要管理员权限或进程已退出`)
        }
        rows.push({
          ...c,
          process: proc?.name || c.process || '未知进程',
          path: exePath,
          commandLine: proc?.commandLine || c.commandLine || '',
          external: true,
          risk: processRisk,
          reasons,
          source: 'scan-finding',
        })
      })
    })
  return rows
}

function parseExternalConnectionsFromEvidence(evidence) {
  const rows = []
  const netstat = /\bTCP\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+ESTABLISHED\s+(\d+)\b/gi
  for (const m of evidence.matchAll(netstat)) {
    const remoteAddress = m[3]
    if (!isExternalIPv4(remoteAddress)) continue
    const pid = Number(m[5])
    const detail = connectionDetailFromEvidence(evidence, pid, remoteAddress)
    rows.push({
      localAddress: m[1],
      localPort: Number(m[2]),
      remoteAddress,
      remotePort: Number(m[4]),
      state: 'Established',
      pid,
      ...detail,
    })
  }
  return rows
}

function connectionDetailFromEvidence(evidence, pid, remoteAddress) {
  const blocks = String(evidence || '').split(/\r?\n\s*\r?\n/)
  const block = blocks.find((x) => x.includes(String(pid)) && x.includes(remoteAddress)) || evidence || ''
  const field = (name) => {
    const re = new RegExp(`^\\s*${name}\\s*:\\s*(.*)$`, 'mi')
    return (String(block).match(re)?.[1] || '').trim()
  }
  return {
    process: field('Process'),
    path: field('Path'),
    commandLine: field('CommandLine'),
  }
}

function mergeNetworkInfo(base, fallbackConnections = []) {
  const fallback = Array.isArray(fallbackConnections) ? fallbackConnections : []
  if (!base && !fallback.length) return base
  const merged = {
    ...(base || {}),
    connections: [...(base?.connections || [])],
    externalConnections: [...(base?.externalConnections || [])],
    listeners: [...(base?.listeners || [])],
    dnsCache: [...(base?.dnsCache || [])],
    dnsServers: [...(base?.dnsServers || [])],
    routes: [...(base?.routes || [])],
    proxies: [...(base?.proxies || [])],
    timestamp: base?.timestamp || scanTimestampFromFallback(fallback),
  }
  merged.connections = mergeConnections([...merged.connections, ...fallback])
  merged.externalConnections = mergeConnections([...merged.externalConnections, ...fallback])
    .filter((c) => c.external || (String(c.state).toLowerCase() === 'established' && isExternalIPv4(c.remoteAddress)))
    .sort((a, b) => severityWeight(b.risk) - severityWeight(a.risk) || String(a.remoteAddress).localeCompare(String(b.remoteAddress)) || (a.remotePort || 0) - (b.remotePort || 0))
  return merged
}

function scanTimestampFromFallback(fallback) {
  return fallback.length ? new Date().toISOString() : ''
}

function mergeConnections(list) {
  const map = new Map()
  ;(list || []).forEach((c) => {
    if (!c) return
    const normalized = {
      ...c,
      localPort: Number(c.localPort) || 0,
      remotePort: Number(c.remotePort) || 0,
      pid: Number(c.pid) || 0,
      external: Boolean(c.external) || (String(c.state).toLowerCase() === 'established' && isExternalIPv4(c.remoteAddress)),
      risk: c.risk || 'medium',
      reasons: c.reasons || [],
    }
    const key = connectionKey(normalized)
    const prev = map.get(key)
    if (!prev) {
      map.set(key, normalized)
      return
    }
    map.set(key, {
      ...prev,
      ...normalized,
      process: preferredText(prev.process, normalized.process),
      path: preferredText(prev.path, normalized.path),
      commandLine: preferredText(prev.commandLine, normalized.commandLine),
      risk: severityWeight(normalized.risk) > severityWeight(prev.risk) ? normalized.risk : prev.risk,
      reasons: Array.from(new Set([...(prev.reasons || []), ...(normalized.reasons || [])].filter(Boolean))),
      external: prev.external || normalized.external,
    })
  })
  return Array.from(map.values())
}

function preferredText(a, b) {
  return String(a || '').trim() ? a : (b || '')
}

function connectionKey(c) {
  return `${c.localAddress || ''}:${c.localPort || 0}->${c.remoteAddress || ''}:${c.remotePort || 0}:pid=${c.pid || 0}`.toLowerCase()
}

function isExternalIPv4(ip) {
  const parts = String(ip || '').split('.').map((x) => Number(x))
  if (parts.length !== 4 || parts.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false
  const [a, b] = parts
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 198 && (b === 18 || b === 19)) return false
  return true
}

function buildAnomalies(scan, processes, hostInfo, networkInfo, persistenceInfo, accounts = [], events = []) {
  const items = []
  const add = (item) => items.push({ id: `A-${items.length + 1}-${item.source || item.category}`, ...item })
  const isSuspiciousRisk = (risk) => ['critical', 'high', 'medium'].includes(risk)
  const reasonText = (reasons) => (reasons || []).filter(Boolean).join('；') || '命中内置风险规则'

  if (hostInfo && isSuspiciousRisk(hostInfo.risk)) {
    add({
      severity: hostInfo.risk,
      category: '主机排查',
      source: hostInfo.hostname || 'host',
      title: `主机系统/权限需要复核：${hostInfo.windowsProductName || 'Windows'} ${hostInfo.displayVersion || hostInfo.windowsVersion || ''}`,
      evidence: `主机：${hostInfo.hostname || '未知'}\n系统版本：${hostInfo.windowsProductName || 'Windows'} ${hostInfo.displayVersion || hostInfo.windowsVersion || ''}\nBuild：${hostInfo.buildNumber || '未知'}${hostInfo.ubr ? `.${hostInfo.ubr}` : ''}\n当前用户：${hostInfo.currentUser || '未知'}\n管理员权限：${hostInfo.isAdmin ? '是' : '否'}\n原因：${reasonText(hostInfo.reasons)}`,
      remediation: '如当前不是管理员权限，请以管理员重新运行客户端以保证进程路径、日志和注册表采集完整；如系统版本过旧，核对补丁基线并优先加固入口面。',
      nav: 'host',
      actionLabel: '看主机排查',
    })
  }

  ;(networkInfo?.externalConnections || [])
    .slice(0, 20)
    .forEach((c) => {
      add({
        severity: c.risk || 'medium',
        category: '网络连接',
        source: `${c.remoteAddress}:${c.remotePort}`,
        title: `外联 IP：${c.remoteAddress}:${c.remotePort} -> ${c.process || '未知进程'} (PID ${c.pid})`,
        evidence: [
          `状态：${c.state}`,
          `本地：${c.localAddress}:${c.localPort}`,
          `远端：${c.remoteAddress}:${c.remotePort}`,
          `PID：${c.pid}`,
          `进程：${c.process || '未知'}`,
          `EXE：${c.path || '未读取到路径'}`,
          `命令行：${c.commandLine || '无'}`,
          `原因：${reasonText(c.reasons)}`,
        ].join('\n'),
        remediation: '核对业务白名单和威胁情报；确认异常后先在主机防火墙/网关阻断该远端 IP，再到进程清除页结束关联进程树，并回查注册表、计划任务、服务和 WMI 是否存在复活项。',
        nav: 'network',
        actionLabel: '看网络连接',
      })
    })

  ;(networkInfo?.listeners || [])
    .filter((c) => c.risk !== 'low' || ['0.0.0.0', '::', '[::]'].includes(c.localAddress))
    .slice(0, 8)
    .forEach((c) => {
      add({
        severity: c.risk === 'low' ? 'info' : c.risk,
        category: '网络连接',
        source: `LISTEN ${c.localPort}`,
        title: `监听端口：${c.localAddress}:${c.localPort} -> ${c.process || '未知进程'} (PID ${c.pid})`,
        evidence: `监听地址：${c.localAddress}:${c.localPort}\nPID：${c.pid}\n进程：${c.process || '未知'}\nEXE：${c.path || '未读取到路径'}\n命令行：${c.commandLine || '无'}\n原因：${reasonText(c.reasons)}`,
        remediation: '核对是否为授权业务端口；非业务监听需要定位进程路径和启动来源，保全证据后停止服务/结束进程并删除持久化入口。',
        nav: 'network',
        actionLabel: '看监听端口',
      })
    })

  ;(networkInfo?.dnsCache || [])
    .filter((d) => d.risk !== 'low')
    .slice(0, 10)
    .forEach((d) => {
      add({
        severity: d.risk || 'medium',
        category: '网络连接',
        source: d.name || d.entry || 'DNS',
        title: `可疑 DNS 缓存：${d.name || d.entry}`,
        evidence: `域名：${d.name || d.entry}\n类型：${d.type || '未知'}\n解析值：${d.data || '无'}\nTTL：${d.timeToLive || 0}\n原因：${reasonText(d.reasons)}`,
        remediation: '关联访问进程、浏览器/应用日志和外联连接；确认非业务后阻断域名/IP，清理相关进程和落地文件，并检查是否存在下载执行链。',
        nav: 'network',
        actionLabel: '看 DNS 缓存',
      })
    })

  ;(networkInfo?.dnsServers || [])
    .filter((d) => d.risk !== 'low')
    .slice(0, 10)
    .forEach((d) => {
      add({
        severity: d.risk || 'medium',
        category: '网络连接',
        source: d.interfaceAlias || 'DNS Server',
        title: `外部 DNS 服务器：${(d.serverAddresses || []).join(', ') || '未知'}`,
        evidence: `网卡：${d.interfaceAlias || '未知'}\nDNS：${(d.serverAddresses || []).join(', ') || '无'}\n原因：${reasonText(d.reasons)}`,
        remediation: '核对 DNS 是否为公司授权解析器；异常时恢复为可信 DNS，追踪配置变更来源，并检查是否有代理、VPN 或恶意服务改写网络配置。',
        nav: 'network',
        actionLabel: '看 DNS 配置',
      })
    })

  ;(networkInfo?.proxies || [])
    .filter((p) => p.risk !== 'low')
    .slice(0, 10)
    .forEach((p) => {
      add({
        severity: p.risk || 'medium',
        category: '网络连接',
        source: p.scope || 'Proxy',
        title: `代理配置异常：${p.scope || 'Proxy'}`,
        evidence: `范围：${p.scope || '未知'}\n启用：${p.enabled ? '是' : '否'}\n服务器：${p.server || p.raw || '无'}\n绕过：${p.bypass || '无'}\n原因：${reasonText(p.reasons)}`,
        remediation: '核实代理是否为授权出口；非授权代理需要导出配置、恢复直连/可信代理，并排查设置代理的进程、脚本和注册表变更。',
        nav: 'network',
        actionLabel: '看代理配置',
      })
    })

  ;(networkInfo?.routes || [])
    .filter((r) => r.risk !== 'low')
    .slice(0, 10)
    .forEach((r) => {
      add({
        severity: r.risk || 'medium',
        category: '网络连接',
        source: r.destinationPrefix || 'Route',
        title: `可疑路由：${r.destinationPrefix} -> ${r.nextHop || 'On-link'}`,
        evidence: `目标：${r.destinationPrefix}\n下一跳：${r.nextHop || 'On-link'}\n网卡：${r.interfaceAlias || '未知'}\nMetric：${r.routeMetric}\n协议：${r.protocol || '未知'}\n原因：${reasonText(r.reasons)}`,
        remediation: '确认是否为授权 VPN/安全设备路由；异常路由先导出 route print 证据，再删除持久路由并回查创建该路由的脚本、服务或计划任务。',
        nav: 'network',
        actionLabel: '看路由表',
      })
    })

  ;(processes || [])
    .filter((p) => isSuspiciousRisk(p.risk))
    .slice(0, 8)
    .forEach((p) => {
      const reasons = reasonText(p.reasons)
      const displayPath = processDisplayPath(p)
      add({
        severity: p.risk,
        category: '进程异常',
        source: `PID ${p.pid}`,
        title: `可疑进程：${p.name || '未知进程'} (${p.pid})`,
        evidence: `${reasons}\n路径：${displayPath}\n命令行：${p.commandLine || '无'}`.trim(),
        remediation: '先记录 PID、PPID、路径、命令行、启动时间和网络连接；确认非业务后进入“进程清除”结束进程树，再回查计划任务、服务、Run 启动项和 WMI 是否存在复活机制。',
        nav: 'processes',
        actionLabel: '去清除进程',
      })
    })

  ;(accounts || [])
    .filter((a) => isSuspiciousRisk(a.risk))
    .slice(0, 12)
    .forEach((a) => {
      add({
        severity: a.risk,
        category: '账号审计',
        source: a.name,
        title: `异常账号：${a.name}`,
        evidence: `账号：${a.name}\n状态：${a.enabled ? '启用' : '禁用'}\n管理员：${a.admin ? '是' : '否'}\n隐藏账户：${isHiddenAccount(a) ? '是' : '否'}\nSID：${a.sid || '未知'}\n最后登录：${fmtDate(a.lastLogon)}\n密码修改：${fmtDate(a.passwordLastSet)}\n原因：${reasonText(a.reasons)}`,
        remediation: '核实账号创建/授权来源；未知启用账号先禁用或移出管理员组，重置相关密码，再按 4624/4625/4672/4720 日志追踪登录源 IP 和横向移动痕迹。',
        nav: 'accounts',
        actionLabel: '看账号审计',
      })
    })

  ;(events || [])
    .filter((e) => isSuspiciousRisk(e.risk))
    .slice(0, 14)
    .forEach((e) => {
      add({
        severity: e.risk,
        category: '日志分析',
        source: `${e.log}:${e.id}`,
        title: eventTitle(e),
        evidence: `日志：${e.log}\nEventID：${e.id}\n时间：${fmtDate(e.time)}\nProvider：${e.provider || '未知'}\n级别：${e.level || '未知'}\n原因：${reasonText(e.reasons)}\n摘要：${eventSummary(e)}`,
        remediation: remediationForFinding({ ruleId: `event_${e.id}`, category: '日志分析', title: eventTitle(e), recommendation: '' }),
        nav: 'logs',
        actionLabel: '看日志分析',
      })
    })

  ;(persistenceInfo?.autoruns || [])
    .filter((a) => a.risk !== 'low')
    .slice(0, 20)
    .forEach((a) => {
      add({
        severity: a.risk || 'medium',
        category: '持久化排查',
        source: a.location || 'Registry',
        title: `注册表启动项：${a.name}`,
        evidence: `位置：${a.location}\n名称：${a.name}\n解析 EXE：${a.path || '未解析'}\n命令：${a.command || '无'}\n原因：${reasonText(a.reasons)}`,
        remediation: '先导出该注册表键和值作为证据；确认非业务后删除启动项，隔离命令指向文件，并检查同路径进程、计划任务、服务和 WMI 是否联动复活。',
        nav: 'persistence',
        actionLabel: '看注册表启动项',
      })
    })

  ;(persistenceInfo?.startupFiles || [])
    .filter((f) => f.risk !== 'low')
    .slice(0, 12)
    .forEach((f) => {
      add({
        severity: f.risk || 'medium',
        category: '持久化排查',
        source: 'Startup Folder',
        title: `启动文件夹文件：${f.fullName}`,
        evidence: `路径：${f.fullName}\n大小：${f.length || 0} bytes\n创建：${fmtDate(f.creationTime)}\n修改：${fmtDate(f.lastWriteTime)}\n原因：${reasonText(f.reasons)}`,
        remediation: '复制样本并计算哈希；确认恶意后删除启动文件夹项，检查快捷方式目标和关联落地文件，再重启前复核是否还有其他持久化入口。',
        nav: 'persistence',
        actionLabel: '看启动文件夹',
      })
    })

  ;(persistenceInfo?.tasks || [])
    .filter((t) => t.risk !== 'low')
    .slice(0, 20)
    .forEach((t) => {
      add({
        severity: t.risk || 'medium',
        category: '持久化排查',
        source: `${t.taskPath || '\\'}${t.taskName || ''}`,
        title: `可疑计划任务：${t.taskName}`,
        evidence: `任务：${t.taskPath || '\\'}${t.taskName || ''}\n状态：${t.state || '未知'}\n作者：${t.author || '未知'}\n执行：${t.execute || '无'}\n参数：${t.arguments || '无'}\n原因：${reasonText(t.reasons)}`,
        remediation: '先导出计划任务 XML；确认恶意后禁用任务，再删除任务和执行文件，最后复查同名服务、Run 启动项和 PowerShell 日志。',
        nav: 'persistence',
        actionLabel: '看计划任务',
      })
    })

  ;(persistenceInfo?.services || [])
    .filter((s) => s.risk !== 'low')
    .slice(0, 20)
    .forEach((s) => {
      add({
        severity: s.risk || 'medium',
        category: '持久化排查',
        source: s.name,
        title: `可疑服务：${s.displayName || s.name}`,
        evidence: `服务名：${s.name}\n显示名：${s.displayName || '无'}\n状态：${s.state || '未知'}\n启动类型：${s.startMode || '未知'}\n运行账号：${s.startName || '未知'}\nPID：${s.processId || 0}\n路径：${s.pathName || '无'}\n原因：${reasonText(s.reasons)}`,
        remediation: '导出服务配置；确认恶意后先停止并禁用服务，再删除服务项和落地文件，检查 7045 事件定位创建者和来源时间线。',
        nav: 'persistence',
        actionLabel: '看服务',
      })
    })

  ;(persistenceInfo?.wmi || [])
    .slice(0, 20)
    .forEach((w) => {
      add({
        severity: w.risk || 'medium',
        category: '持久化排查',
        source: `WMI ${w.kind || ''}`,
        title: `WMI 永久订阅：${w.name || w.kind}`,
        evidence: `类型：${w.kind || '未知'}\n名称：${w.name || '未知'}\nQuery：${w.query || '无'}\nCommand：${w.command || '无'}\n原因：${reasonText(w.reasons)}`,
        remediation: '导出 root/subscription 下 Filter、Consumer、Binding；确认恶意后删除订阅对象，并排查创建该 WMI 订阅的 PowerShell/脚本日志。',
        nav: 'persistence',
        actionLabel: '看 WMI',
      })
    })

  ;(scan?.findings || [])
    .filter((f) => f.severity !== 'pass')
    .filter((f) => !(f.ruleId === 'win.external_established' && (networkInfo?.externalConnections || []).length))
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
    .slice(0, 12)
    .forEach((f) => {
      add({
        severity: f.severity || 'info',
        category: f.category || '扫描发现',
        source: f.ruleId || f.sourceTaskId || 'finding',
        title: f.title,
        evidence: `${f.evidence || '无证据片段'}${f.sourceTaskId ? `\n来源任务：${f.sourceTaskId}` : ''}`,
        remediation: remediationForFinding(f),
        nav: navForFinding(f),
        actionLabel: actionLabelForFinding(f),
      })
    })

  return items.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
}

function filterModuleAnomalies(active, items) {
  const textOf = (item) => `${item.category || ''} ${item.source || ''} ${item.title || ''} ${item.evidence || ''} ${item.nav || ''}`.toLowerCase()
  const hasAny = (text, keys) => keys.some((k) => text.includes(k.toLowerCase()))
  return items.filter((item) => {
    const text = textOf(item)
    switch (active) {
      case 'host':
        return item.nav === 'host' || hasAny(text, ['进程', '网络', '账户', '文件', '防护', '基础', '资产', '系统版本', 'build', 'process', 'network', 'account', 'file', 'defender', 'basic'])
      case 'network':
        return item.nav === 'network' || item.category === '网络连接' || hasAny(`${item.source || ''} ${item.title || ''}`.toLowerCase(), ['win.external', 'win.dns', 'win.route', 'win.proxy'])
      case 'persistence':
        return item.nav === 'persistence' || item.category === '持久化排查' || hasAny(text, ['持久化', '服务', '计划任务', '启动项', 'wmi', 'autorun', 'service', 'scheduled', 'persistence', '7045'])
      case 'logs':
        if (item.category === '账户审计') return false
        return hasAny(text, ['日志分析', '日志清理', '安全日志', 'powershell', '4104', '1102', 'eventlog', 'web 日志', 'webshell', 'web.suspicious', 'system-events', 'powershell-events', 'web-logs', 'log'])
      case 'accounts':
        return item.category === '账户审计' || hasAny(text, ['账户', '账号', '登录', '管理员组', '4624', '4625', '4672', '4720', '4722', '4726', 'bruteforce', 'privileged_logon', 'account_change', 'users', 'account', 'login'])
      case 'files':
        return hasAny(text, ['文件', '临时', '下载', 'prefetch', 'ads', 'webshell', 'web', 'files', 'file', 'path'])
      case 'tools':
        return hasAny(text, ['采集', 'collector', 'task_error', '工具', 'skill'])
      case 'settings':
        return hasAny(text, ['采集', 'collector', 'profile', 'timeout', '设置'])
      default:
        return true
    }
  })
}

function remediationForFinding(f) {
  const text = `${f.ruleId || ''} ${f.category || ''} ${(f.tags || []).join(' ')} ${f.title || ''}`.toLowerCase()
  if (text.includes('external') || text.includes('network') || text.includes('网络') || text.includes('外部')) {
    return '关联 PID、进程路径和业务白名单；确认非业务外联后先在主机防火墙/网关临时阻断，再定位进程并结束进程树，保全 netstat、DNS 缓存和连接时间线。'
  }
  if (text.includes('wmi') || text.includes('service') || text.includes('服务') || text.includes('计划') || text.includes('persistence') || text.includes('持久化')) {
    return '先导出服务、计划任务、WMI Filter/Consumer/Binding 和注册表启动项；确认恶意后禁用，再删除配置和落地文件，最后重跑排查验证是否复活。'
  }
  if (text.includes('account') || text.includes('login') || text.includes('账户') || text.includes('登录') || text.includes('4625') || text.includes('4672')) {
    return '核实账号变更和登录来源；未知账号先禁用或移出管理员组，重置相关密码，按源 IP、登录类型和同账号横向扩面排查。'
  }
  if (text.includes('log') || text.includes('日志') || text.includes('1102')) {
    return '不要重启主机；立即保全安全日志、系统日志、EDR/SIEM、域控和网关日志，定位清理日志的账号、会话和来源 IP。'
  }
  if (text.includes('defender') || text.includes('防护')) {
    return '确认是否授权策略；非授权时恢复实时防护，删除未知排除项，追踪策略变更来源，并对排除路径做样本取证。'
  }
  if (text.includes('web') || text.includes('post') || text.includes('get')) {
    return '导出完整访问日志，先按 POST、GET、源 IP、URI 和 User-Agent 聚合；隔离可疑 Web 文件，封禁攻击源并修补入口漏洞。'
  }
  if (text.includes('path') || text.includes('file') || text.includes('临时') || text.includes('脚本')) {
    return '先复制样本、计算哈希并记录时间戳；确认恶意后结束关联进程、删除持久化，再隔离或删除落地文件。'
  }
  return f.recommendation || '保全证据后结合业务基线复核；确认恶意再执行清除、封禁、隔离和加固。'
}

function navForFinding(f) {
  const text = `${f.sourceTaskId || ''} ${f.category || ''} ${f.ruleId || ''}`.toLowerCase()
  if (text.includes('network')) return 'network'
  if (text.includes('service') || text.includes('wmi') || text.includes('persistence')) return 'persistence'
  if (text.includes('account') || text.includes('login') || text.includes('bruteforce') || text.includes('privileged') || text.includes('账户')) return 'accounts'
  if (text.includes('security') || text.includes('eventlog') || text.includes('powershell') || text.includes('web-logs') || text.includes('log')) return 'logs'
  if (text.includes('file') || text.includes('web')) return 'files'
  return 'report'
}

function actionLabelForFinding(f) {
  const nav = navForFinding(f)
  if (nav === 'network') return '看网络连接'
  if (nav === 'persistence') return '看持久化'
  if (nav === 'accounts') return '看账号审计'
  if (nav === 'logs') return '看日志分析'
  if (nav === 'files') return '看文件取证'
  return '看报告证据'
}

function formatFullResponseText({ scan, status, processes, hostInfo, accounts = [], events = [], networkInfo, persistenceInfo, anomalies, logLines }) {
  const suspicious = (processes || []).filter((p) => ['critical', 'high', 'medium'].includes(p.risk))
  const lines = []
  lines.push('=== 应急响应完整输出 ===')
  lines.push(`主机：${status?.hostname || 'localhost'}`)
  lines.push(`时间：${new Date().toLocaleString()}`)
  lines.push(`扫描状态：${scan?.status || '未启动'}  Profile：${scan?.options?.profile || 'combined'}`)
  lines.push(`输出目录：${scan?.outputDir || '未生成'}`)
  lines.push('')
  lines.push('=== 主机排查：系统版本与权限 ===')
  if (hostInfo) {
    lines.push(`主机名：${hostInfo.hostname || status?.hostname || '未知'}`)
    lines.push(`系统版本：${hostInfo.windowsProductName || 'Windows'} ${hostInfo.displayVersion || hostInfo.windowsVersion || ''}`)
    lines.push(`Build：${hostInfo.buildNumber || '未知'}${hostInfo.ubr ? `.${hostInfo.ubr}` : ''}  架构：${hostInfo.architecture || '未知'}`)
    lines.push(`当前用户：${hostInfo.currentUser || '未知'}  SID=${hostInfo.userSid || '未知'}  权限=${hostInfo.isAdmin ? '管理员' : '普通权限'}`)
    lines.push(`域/工作组：${hostInfo.domain || '未知'}  型号：${hostInfo.manufacturer || '未知'} ${hostInfo.model || ''}`)
    lines.push(`安装时间：${fmtDate(hostInfo.installDate)}  最近启动：${fmtDate(hostInfo.lastBootTime)}  PowerShell=${hostInfo.powerShellVersion || '未知'}`)
    lines.push(`风险结论：[${severityLabel[hostInfo.risk] || hostInfo.risk}] ${(hostInfo.reasons || []).join('；')}`)
    ;(hostInfo.ipAddresses || []).forEach((ip) => lines.push(`IP：${ip.interfaceAlias || '未知网卡'} ${ip.ipAddress}/${ip.prefixLength || 0}`))
    ;(hostInfo.hotfixes || []).slice(0, 20).forEach((h) => lines.push(`补丁：${h.hotFixId || ''} ${h.description || ''} ${fmtDate(h.installedOn)} ${h.installedBy || ''}`))
  } else {
    lines.push('暂无主机结构化接口数据；可在主机排查页点击“刷新主机”。')
  }
  lines.push('')
  lines.push('=== 异常发现与清除建议 ===')
  if (anomalies.length) {
    anomalies.forEach((a, idx) => {
      lines.push(`${idx + 1}. [${severityLabel[a.severity] || a.severity}] ${a.title}`)
      lines.push(`   分类：${a.category}  来源：${a.source}`)
      lines.push(`   证据：${singleLine(a.evidence)}`)
      lines.push(`   清除/处置：${a.remediation}`)
    })
  } else {
    lines.push('未命中内置异常规则；建议结合业务基线复核外联、账号、持久化和日志清理。')
  }
  lines.push('')
  lines.push('=== 可疑进程摘要 ===')
  if (suspicious.length) {
    suspicious.forEach((p) => {
      lines.push(`[${severityLabel[p.risk] || p.risk}] PID=${p.pid} PPID=${p.ppid} Name=${p.name}`)
      lines.push(`Path=${processDisplayPath(p)}`)
      lines.push(`CommandLine=${p.commandLine || '无'}`)
      lines.push(`Reason=${(p.reasons || []).join('；')}`)
    })
  } else {
    lines.push('暂无可疑进程数据。')
  }
  lines.push('')
  lines.push('=== 网络连接：外联 IP、PID、进程与 EXE ===')
  const external = networkInfo?.externalConnections || []
  if (external.length) {
    buildExternalPidGroups(external).forEach((group) => {
      lines.push(`[${severityLabel[group.risk] || group.risk}] Process=${group.process || '未知'} PID=${group.pid || '未知'} 外联IP=${group.ips.length} 连接=${group.connections.length}`)
      lines.push(`EXE=${group.path || '未读取到路径'}`)
      lines.push(`CommandLine=${group.commandLine || '无'}`)
      lines.push(`Reason=${(group.reasons || []).join('；') || '同一 PID 外联连接聚合'}`)
      group.connections.forEach((c) => {
        lines.push(`  ${c.state} ${c.localAddress}:${c.localPort} -> ${c.remoteAddress}:${c.remotePort}`)
      })
    })
  } else {
    lines.push('未发现外部 ESTABLISHED 连接。')
  }
  lines.push('')
  lines.push('=== 网络配置：监听端口 / DNS / 代理 / 路由 ===')
  ;(networkInfo?.listeners || []).slice(0, 120).forEach((c) => {
    lines.push(`[${severityLabel[c.risk] || c.risk}] LISTEN ${c.localAddress}:${c.localPort} PID=${c.pid} Process=${c.process || '未知'} EXE=${c.path || '未读取到路径'}`)
  })
  ;(networkInfo?.dnsServers || []).forEach((d) => {
    lines.push(`[${severityLabel[d.risk] || d.risk}] DNS ${d.interfaceAlias || '未知网卡'} => ${(d.serverAddresses || []).join(', ') || '无'} Reason=${(d.reasons || []).join('；')}`)
  })
  ;(networkInfo?.dnsCache || []).filter((d) => d.risk !== 'low').slice(0, 80).forEach((d) => {
    lines.push(`[${severityLabel[d.risk] || d.risk}] DNSCache ${d.name || d.entry} ${d.type || ''} ${d.data || ''} TTL=${d.timeToLive || 0} Reason=${(d.reasons || []).join('；')}`)
  })
  ;(networkInfo?.proxies || []).forEach((p) => {
    lines.push(`[${severityLabel[p.risk] || p.risk}] Proxy ${p.scope || ''} Enabled=${p.enabled ? 'true' : 'false'} Server=${p.server || p.raw || '无'} Bypass=${p.bypass || '无'} Reason=${(p.reasons || []).join('；')}`)
  })
  ;(networkInfo?.routes || [])
    .filter((r, idx) => r.risk !== 'low' || r.destinationPrefix === '0.0.0.0/0' || idx < 20)
    .slice(0, 120)
    .forEach((r) => {
      lines.push(`[${severityLabel[r.risk] || r.risk}] Route ${r.destinationPrefix} -> ${r.nextHop || 'On-link'} If=${r.interfaceAlias || '未知'} Metric=${r.routeMetric} Protocol=${r.protocol || '未知'} Reason=${(r.reasons || []).join('；')}`)
    })
  if (!networkInfo) lines.push('暂无网络结构化接口数据；可在网络连接页点击“刷新网络”。')
  lines.push('')
  lines.push('=== 持久化：注册表启动项 / 启动文件夹 / 计划任务 / 服务 / WMI ===')
  const autoruns = persistenceInfo?.autoruns || []
  if (autoruns.length) {
    autoruns.forEach((a) => {
      lines.push(`[${severityLabel[a.risk] || a.risk}] Registry ${a.location || ''} :: ${a.name || ''}`)
      lines.push(`Path=${a.path || '未解析'} Command=${a.command || '无'} Reason=${(a.reasons || []).join('；')}`)
    })
  } else {
    lines.push('未发现注册表 Run/RunOnce/Winlogon 启动项或尚未刷新持久化数据。')
  }
  ;(persistenceInfo?.startupFiles || []).forEach((f) => {
    lines.push(`[${severityLabel[f.risk] || f.risk}] StartupFile ${f.fullName} Size=${f.length || 0} Created=${fmtDate(f.creationTime)} Modified=${fmtDate(f.lastWriteTime)} Reason=${(f.reasons || []).join('；')}`)
  })
  ;(persistenceInfo?.tasks || []).slice(0, 180).forEach((t) => {
    lines.push(`[${severityLabel[t.risk] || t.risk}] Task ${t.taskPath || '\\'}${t.taskName || ''} State=${t.state || '未知'} Author=${t.author || '未知'}`)
    lines.push(`Execute=${t.execute || '无'} Args=${t.arguments || '无'} Reason=${(t.reasons || []).join('；')}`)
  })
  ;(persistenceInfo?.services || [])
    .filter((s, idx) => s.risk !== 'low' || idx < 80)
    .slice(0, 180)
    .forEach((s) => {
      lines.push(`[${severityLabel[s.risk] || s.risk}] Service ${s.name || ''} Display=${s.displayName || ''} State=${s.state || ''} Start=${s.startMode || ''} User=${s.startName || ''} PID=${s.processId || 0}`)
      lines.push(`Path=${s.pathName || '无'} Reason=${(s.reasons || []).join('；')}`)
    })
  ;(persistenceInfo?.wmi || []).forEach((w) => {
    lines.push(`[${severityLabel[w.risk] || w.risk}] WMI ${w.kind || ''} ${w.name || ''}`)
    lines.push(`Query=${w.query || '无'} Command=${w.command || '无'} Reason=${(w.reasons || []).join('；')}`)
  })
  if (!persistenceInfo) lines.push('暂无持久化结构化接口数据；可在持久化排查页点击“刷新持久化”。')
  lines.push('')
  lines.push('=== 账号审计：本地账号列表 ===')
  if (accounts.length) {
    accounts.forEach((a) => {
      lines.push(`[${severityLabel[a.risk] || a.risk}] ${a.name} ${a.enabled ? '启用' : '禁用'} ${a.admin ? '管理员' : '普通用户'} ${isHiddenAccount(a) ? '隐藏账户' : '正常'}`)
      lines.push(`SID=${a.sid || '未知'} LastLogon=${fmtDate(a.lastLogon)} PasswordLastSet=${fmtDate(a.passwordLastSet)}`)
      lines.push(`Reason=${(a.reasons || []).join('；')}`)
    })
  } else {
    lines.push('暂无账号接口数据；可在账号审计页点击“刷新账号”。')
  }
  lines.push('')
  lines.push('=== 日志分析：关键事件 ===')
  if (events.length) {
    events.forEach((e) => {
      lines.push(`[${severityLabel[e.risk] || e.risk}] ${e.log} EventID=${e.id} ${fmtDate(e.time)} ${e.provider || ''}`)
      lines.push(`Reason=${(e.reasons || []).join('；')}`)
      lines.push(`Message=${singleLine(e.message)}`)
    })
  } else {
    lines.push('暂无日志接口数据；可在日志分析页点击“刷新日志”。')
  }
  lines.push('')
  lines.push('=== 扫描发现 ===')
  ;(scan?.findings || []).forEach((f) => {
    lines.push(`[${severityLabel[f.severity] || f.severity}] ${f.title}`)
    lines.push(`Rule=${f.ruleId} Task=${f.sourceTaskId} Category=${f.category}`)
    lines.push(`Evidence=${singleLine(f.evidence)}`)
    lines.push(`Recommendation=${f.recommendation}`)
  })
  if (!scan?.findings?.length) lines.push('暂无扫描发现。')
  lines.push('')
  lines.push('=== 任务执行状态 ===')
  ;(scan?.results || []).forEach((r) => {
    lines.push(`${fmtTime(r.finishedAt)} [${r.status}] ${r.taskId} ${r.title} ${r.durationMs}ms`)
    if (r.preview) lines.push(r.preview)
  })
  if (!scan?.results?.length) lines.push('暂无任务结果。')
  lines.push('')
  lines.push('=== 客户端执行日志 ===')
  logLines.forEach((l) => lines.push(`${l.time} ${l.type?.toUpperCase() || 'INFO'} ${l.text}`))
  return lines.join('\n')
}

function filterFullResponse(text, filter) {
  const q = filter.trim()
  if (!q) return text
  try {
    const re = new RegExp(q, 'i')
    return text.split(/\r?\n/).filter((line) => re.test(line)).join('\n')
  } catch {
    const low = q.toLowerCase()
    return text.split(/\r?\n/).filter((line) => line.toLowerCase().includes(low)).join('\n')
  }
}

function singleLine(text) {
  return cleanText(text).replace(/\s+/g, ' ').trim()
}

function cleanText(text) {
  return (text || '')
    .replace(/\uFFFD+/g, '')
    .replace(/[ \t]+/g, ' ')
    .trim()
}

function toAuditEventRow(e) {
  const message = e.message || ''
  const ip = normalizeAuditValue(e.ip) || normalizeAuditValue(extractEventField(message, ['Source Network Address', 'Source Address', 'Client Address', 'IpAddress', 'IP Address', '源网络地址', '源地址', '客户端地址', 'IP 地址']))
  const port = normalizeAuditValue(e.port) || normalizeAuditValue(extractEventField(message, ['Source Port', 'Client Port', 'IpPort', '源端口', '客户端端口']))
  const user = normalizeAuditValue(e.user) || extractEventUser(message) || extractEventField(message, ['Target User Name', 'Account Name', 'User Name', '目标用户名', '目标帐户名', '目标账户名', '用户名', '帐户名', '账户名'])
  const rawType = normalizeAuditValue(e.logonType) || extractEventField(message, ['Logon Type', '登录类型'])
  const id = Number(e.id) || 0
  return {
    event: e,
    category: auditLogCategoryById[id] || 'other',
    eventId: id || e.id || 'LOG',
    timeRaw: e.time || '',
    time: fmtDate(e.time),
    loginType: loginTypeLabel(rawType, id),
    ip,
    port,
    user: normalizeAuditValue(user),
    log: e.log || 'Unknown',
    provider: e.provider || '',
    title: eventTitle(e),
    summary: eventSummary(e),
    risk: e.risk || 'low',
  }
}

function extractEventUser(message) {
  return normalizeAuditValue(
    extractEventFieldFromSection(message, ['New Logon', '新登录', '新登入'], ['Account Name', 'User Name', '帐户名', '账户名', '用户名']) ||
    extractEventFieldFromSection(message, ['Account For Which Logon Failed', '登录失败的帐户', '登录失败的账户', '帐户登录失败', '账户登录失败'], ['Account Name', 'User Name', '帐户名', '账户名', '用户名']) ||
    extractEventFieldFromSection(message, ['Target Account', '目标帐户', '目标账户'], ['Account Name', 'Target User Name', 'User Name', '帐户名', '账户名', '用户名']) ||
    extractEventFieldFromSection(message, ['Member', '成员'], ['Account Name', 'Member Name', '帐户名', '账户名', '成员名'])
  )
}

// 这些事件本身就没有源 IP（账户操作/日志服务关闭/异常关机/审计清除/日志启动），
// 空值时显示“本地”或“—”，而不是误导性的问号。
function noIpEvent(row) {
  const id = Number(row?.eventId)
  const localCats = ['account', 'service', 'cleared', 'serviceCreate', 'procCreate']
  const localIds = [6005, 6006, 6008, 1100, 1102, 4688, 7045, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740]
  return localCats.includes(row?.category) || localIds.includes(id)
}

function extractEventFieldFromSection(message, sectionNames, labels) {
  const text = String(message || '')
  if (!text) return ''
  for (const section of sectionNames) {
    const idx = text.toLowerCase().indexOf(String(section).toLowerCase())
    if (idx < 0) continue
    const chunk = text.slice(idx, idx + 1400)
    const value = extractEventField(chunk, labels)
    if (value) return value
  }
  return ''
}

function extractEventField(message, labels) {
  const text = String(message || '')
  if (!text) return ''
  for (const label of labels) {
    const escaped = escapeRegExp(label)
    const re = new RegExp(`${escaped}\\s*[:：]\\s*([^\\r\\n]+)`, 'i')
    const match = text.match(re)
    if (match?.[1]) return match[1].trim()
  }
  return ''
}

function normalizeAuditValue(value) {
  const text = cleanText(value)
  if (!text || text === '-' || /^N\/A$/i.test(text) || /^::1$/.test(text)) return ''
  return text.replace(/^\\+|\\+$/g, '')
}

function loginTypeLabel(value, eventId) {
  const raw = normalizeAuditValue(value)
  const type = Number((raw.match(/\d+/) || [])[0])
  const labels = {
    2: '2 · 交互登录',
    3: '3 · 网络登录',
    4: '4 · 批处理',
    5: '5 · 服务登录',
    7: '7 · 解锁',
    8: '8 · 明文网络',
    9: '9 · 新凭据',
    10: '10 · RDP远程',
    11: '11 · 缓存交互',
  }
  if (labels[type]) return labels[type]
  const fallback = {
    1100: '日志服务关闭',
    1102: '审计日志清除',
    4648: '显式凭据登录',
    4672: '特权登录',
    4778: 'RDP会话重连',
    4779: 'RDP会话断开',
    21: 'RDP会话登录',
    22: 'RDP会话重连',
    24: 'RDP会话断开',
    25: 'RDP重新连接',
    4688: '进程创建',
    7045: '新服务安装',
    4720: '创建账户',
    4722: '启用账户',
    4723: '修改密码尝试',
    4724: '重置密码',
    4725: '禁用账户',
    4726: '删除账户',
    4728: '加入全局组',
    4729: '移出全局组',
    4732: '加入本地组',
    4733: '移出本地组',
    4738: '账户属性变更',
    4740: '账户锁定',
    6006: '事件日志服务停止',
  }
  return fallback[Number(eventId)] || raw || eventTitle({ id: eventId, reasons: [] })
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}


function eventTitle(e) {
  const reason = (e.reasons || [])[0]
  if (reason && !reason.startsWith('关键日志事件')) return reason
  const map = {
    400: 'PowerShell 引擎启动',
    403: 'PowerShell 引擎停止',
    600: 'PowerShell Provider 加载',
    800: 'PowerShell 管道执行',
    4103: 'PowerShell 模块日志',
    4104: 'PowerShell 脚本块日志',
    4624: '登录成功事件',
    4625: '登录失败事件',
    4648: '显式凭据登录事件',
    4672: '特权登录事件',
    4720: '账号创建事件',
    4722: '账号启用事件',
    4723: '账号密码修改尝试',
    4724: '账号密码重置事件',
    4725: '账号禁用事件',
    4726: '账号删除事件',
    4728: '成员加入全局组',
    4729: '成员移出全局组',
    4732: '成员加入本地组',
    4733: '成员移出本地组',
    4738: '账号属性变更事件',
    4740: '账号锁定事件',
    4771: 'Kerberos 预认证失败',
    4776: 'NTLM 凭据验证',
    4778: 'RDP 会话重连',
    4779: 'RDP 会话断开',
    21: 'RDP 会话登录',
    22: 'RDP 会话重连',
    24: 'RDP 会话断开',
    25: 'RDP 重新连接成功',
    4688: '进程创建事件',
    7045: '新服务安装事件',
    7040: '服务启动类型变更',
    1100: '事件日志服务关闭',
    1102: '安全日志清理事件',
    6006: '事件日志服务停止',
  }
  return map[e.id] || `关键日志事件 ${e.id || ''}`.trim()
}

function eventSummary(e) {
  const cleaned = cleanText(e.message)
  if (!cleaned || cleaned.length < 8) {
    return `${eventTitle(e)}。日志：${e.log}，Provider：${e.provider || '未知'}。`
  }
  const badChars = ((e.message || '').match(/\uFFFD/g) || []).length
  if (badChars >= 3) {
    return `${eventTitle(e)}。原始系统消息包含本地编码字符，已隐藏乱码；请按 Event ID、时间、Provider 在完整响应或事件查看器中复核。`
  }
  return cleaned.slice(0, 260)
}


function fileNameFromPath(path) {
  const text = String(path || '')
  return text.split(/[\\/]/).filter(Boolean).pop() || ''
}

function fmtBytes(value) {
  const n = Number(value || 0)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`
}

function formatNumber(value, digits = 1) {
  const n = Number(value || 0)
  if (!Number.isFinite(n)) return '0'
  if (n === 0) return '0'
  return n.toFixed(digits).replace(/\.0+$/, '').replace(/(\.\d*[1-9])0+$/, '$1')
}

function fmtDate(t) {
  if (!t) return '未知'
  try { return new Date(t).toLocaleString() } catch { return String(t) }
}

// 截断中间部分，保留首尾，用于显示长命令行/路径
function truncateMid(text, max = 80) {
  const s = String(text || '')
  if (s.length <= max) return s
  const head = Math.ceil((max - 3) / 2)
  const tail = Math.floor((max - 3) / 2)
  return `${s.slice(0, head)}...${s.slice(-tail)}`
}

function severityWeight(sev) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1, pass: 0 }[sev] || 1
}

async function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand('copy')
  textarea.remove()
}

function fmtTime(t) {
  if (!t) return new Date().toLocaleTimeString()
  try { return new Date(t).toLocaleTimeString() } catch { return '' }
}

function loadAIConfig() {
  try {
    const raw = window.localStorage.getItem('ir-ai-config')
    if (!raw) return defaultAIConfig
    return { ...defaultAIConfig, ...JSON.parse(raw) }
  } catch {
    return defaultAIConfig
  }
}

function saveAIConfig(config) {
  try {
    window.localStorage.setItem('ir-ai-config', JSON.stringify({
      baseUrl: config.baseUrl || '',
      apiKey: config.apiKey || '',
      model: config.model || '',
    }))
  } catch {
    // WebView localStorage may be unavailable in restricted environments.
  }
}

function buildAIEvidence({ status, options, scan, processes, hostInfo, accounts, events, networkInfo, persistenceInfo, anomalies }) {
  const riskyProcesses = (processes || []).filter((p) => ['critical', 'high', 'medium'].includes(p.risk))
  const riskyAccounts = (accounts || []).filter((a) => ['critical', 'high', 'medium'].includes(a.risk) || a.admin)
  const riskyEvents = (events || []).filter((e) => ['critical', 'high', 'medium'].includes(e.risk))
  const riskyAutoruns = (persistenceInfo?.autoruns || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk))
  const riskyStartupFiles = (persistenceInfo?.startupFiles || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk))
  const riskyTasks = (persistenceInfo?.tasks || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk))
  const riskyServices = (persistenceInfo?.services || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk))
  const riskyWMI = (persistenceInfo?.wmi || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk))
  const externalConnections = networkInfo?.externalConnections || []
  const externalByPid = buildExternalPidGroups(externalConnections).map((group) => ({
    pid: group.pid,
    process: group.process,
    path: group.path,
    commandLine: compactText(group.commandLine || '', 500),
    risk: group.risk,
    ips: group.ips,
    ports: group.ports,
    reasons: group.reasons,
  }))
  return {
    generatedAt: new Date().toISOString(),
    auditContext: {
      purpose: 'Windows 应急响应 AI 复核，要求区分确认风险、高度可疑、需白名单确认、可能误报和证据不足。',
      falsePositiveGuidance: [
        '常用公共 DNS 只能按企业策略复核，不要单独判恶意。',
        'Microsoft Windows 系统计划任务路径为 \\Microsoft\\Windows\\ 且作者为 Microsoft Corporation、执行位于 system32 时，默认按低风险或可能误报处理。',
        'AppData/用户目录下常见应用自启动项只能判为需业务白名单确认，除非存在脚本宿主、下载执行、无签名、近期异常落地或关联外联证据。',
        'PowerShell EncodedCommand 若解码为 Rust command-safety layer、stdin JSON request parser、Invoke-ParseRequest/Write-Response 等本地自动化执行层，不要直接定性为 C2。',
        'WMI 只有 EventFilter/Query 不能确认后门，必须结合 Consumer/Binding/CommandLineTemplate/ScriptText 或创建日志。',
        '443 外联到云厂商、CDN、常见应用服务时只列 IOC 和待确认，不能在无威胁情报/无异常进程/无数据外传证据时直接判高危。',
      ],
    },
    host: {
      hostname: status?.hostname || hostInfo?.hostname || 'unknown',
      os: status?.os,
      arch: status?.arch,
      currentUser: hostInfo?.currentUser,
      isAdmin: hostInfo?.isAdmin,
      windowsProductName: hostInfo?.windowsProductName,
      displayVersion: hostInfo?.displayVersion,
      buildNumber: hostInfo?.buildNumber,
      domain: hostInfo?.domain,
      installDate: hostInfo?.installDate,
      lastBootTime: hostInfo?.lastBootTime,
      risk: hostInfo?.risk,
      reasons: hostInfo?.reasons,
      ipAddresses: limitItems(hostInfo?.ipAddresses, 30),
      hotfixes: limitItems(hostInfo?.hotfixes, 30),
    },
    scan: scan ? {
      id: scan.id,
      status: scan.status,
      profile: scan.options?.profile || options.profile,
      outputDir: scan.outputDir,
      reportPath: scan.reportPath,
      findings: limitItems(scan.findings || [], 120),
      taskPreviews: limitItems((scan.results || []).map((r) => ({
        taskId: r.taskId,
        title: r.title,
        category: r.category,
        status: r.status,
        preview: compactText(r.preview || '', 1800),
      })), 40),
    } : { status: 'not_started', options },
    processes: {
      risky: limitItems(riskyProcesses, 80).map(pickProcessEvidence),
      sample: limitItems((processes || []).slice(0, 40), 40).map(pickProcessEvidence),
    },
    accounts: {
      riskyOrAdmin: limitItems(riskyAccounts, 80),
      sample: limitItems(accounts || [], 80),
    },
    logs: {
      risky: limitItems(riskyEvents, 120),
      recentSample: limitItems(events || [], 120),
    },
    network: {
      externalConnections: limitItems(externalConnections, 120),
      externalByPid: limitItems(externalByPid, 80),
      listeners: limitItems(networkInfo?.listeners || [], 80),
      riskyDNSCache: limitItems((networkInfo?.dnsCache || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk)), 80),
      dnsServers: limitItems(networkInfo?.dnsServers || [], 40),
      riskyRoutes: limitItems((networkInfo?.routes || []).filter((x) => ['critical', 'high', 'medium'].includes(x.risk)), 80),
      proxies: limitItems(networkInfo?.proxies || [], 40),
    },
    persistence: {
      autoruns: limitItems(riskyAutoruns.length ? riskyAutoruns : persistenceInfo?.autoruns || [], 120),
      startupFiles: limitItems(riskyStartupFiles.length ? riskyStartupFiles : persistenceInfo?.startupFiles || [], 80),
      tasks: limitItems(riskyTasks.length ? riskyTasks : persistenceInfo?.tasks || [], 120),
      services: limitItems(riskyServices.length ? riskyServices : persistenceInfo?.services || [], 120),
      wmi: limitItems(riskyWMI.length ? riskyWMI : persistenceInfo?.wmi || [], 80),
    },
    anomalies: limitItems(anomalies || [], 120),
  }
}

function pickProcessEvidence(p) {
  const decodedCommand = p.decodedCommand || decodePowerShellEncodedCommandClient(p.commandLine)
  const trustHints = [...(p.trustHints || []), ...processTrustHints(p, decodedCommand)]
  return {
    pid: p.pid,
    ppid: p.ppid,
    name: p.name,
    path: processDisplayPath(p),
    commandLine: compactText(p.commandLine || '', 900),
    decodedCommand: compactText(decodedCommand || '', 1200),
    trustHints,
    creationDate: p.creationDate,
    cpu: p.cpu,
    memoryMB: p.memoryMB,
    risk: p.risk,
    reasons: p.reasons,
  }
}

function processTrustHints(proc, decodedCommand) {
  const hints = []
  const decoded = String(decodedCommand || '').toLowerCase()
  if (decoded.includes('rust command-safety layer') || decoded.includes('long-lived powershell ast parser')) {
    hints.push('EncodedCommand 解码内容疑似本地自动化/命令安全层，AI 不应仅凭该项判定 C2')
  }
  if (String(proc?.path || '').toLowerCase().includes('\\windows\\system32\\windowspowershell\\') && hints.length) {
    hints.push('PowerShell 主程序位于系统目录，需结合父进程、网络连接和持久化证据复核')
  }
  return hints
}

function decodePowerShellEncodedCommandClient(commandLine) {
  const match = String(commandLine || '').match(/(?:^|\s)(?:-|\/)(?:encodedcommand|enc|ec|e)\s+([A-Za-z0-9+/=]+)/i)
  if (!match?.[1] || typeof atob !== 'function') return ''
  try {
    const binary = atob(match[1])
    const bytes = Array.from(binary, (ch) => ch.charCodeAt(0))
    if (bytes.length >= 2 && bytes[1] === 0) {
      const chars = []
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        chars.push(String.fromCharCode(bytes[i] | (bytes[i + 1] << 8)))
      }
      return chars.join('').trim()
    }
    return binary.trim()
  } catch {
    return ''
  }
}

function limitItems(items, n) {
  return Array.isArray(items) ? items.slice(0, n) : []
}

function compactText(text, n = 1000) {
  const s = String(text || '').trim()
  if (s.length <= n) return s
  return `${s.slice(0, n)}...`
}

function sectionBetween(text, start, end) {
  const s = String(text || '')
  const i = s.indexOf(start)
  if (i < 0) return ''
  const from = i + start.length
  const j = end ? s.indexOf(end, from) : -1
  return s.slice(from, j >= 0 ? j : undefined)
}

function sectionAfter(text, start) {
  return sectionBetween(text, start, '')
}

function extractFileRows(text, limit = 80) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('---') && !/^FullName\s+Length|^Name\s+Length|^-{3,}/i.test(line))
    .filter((line) => /[A-Za-z]:\\|\.pf\b|\.(exe|dll|ps1|vbs|js|bat|cmd)\b/i.test(line))
    .slice(0, limit)
    .map((line) => {
      const path = extractWindowsPath(line)
      return { path, text: line, meta: path && path !== line ? line.replace(path, '').trim() : line }
    })
}

function extractInterestingLines(text, limit = 80, re = /[A-Za-z]:\\|:\$DATA|POST|GET|cmd=|exec=|shell=|upload|base64|powershell|whoami/i) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && re.test(line))
    .slice(0, limit)
    .map((line) => {
      const path = extractWindowsPath(line)
      return { path, text: line, meta: path && path !== line ? line.replace(path, '').trim() : line }
    })
}

function extractWindowsPath(line) {
  const m = String(line || '').match(/[A-Za-z]:\\[^\s|<>"]+/)
  return m ? m[0].replace(/[),;]+$/, '') : ''
}

async function fetchText(path) {
  const res = await fetch(path)
  const text = await res.text()
  if (!res.ok) throw new Error(text || `HTTP ${res.status}`)
  return text
}

async function api(path, init = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json', ...(init.headers || {}) }, ...init })
  const contentType = res.headers.get('content-type') || ''
  const text = await res.text()
  if (!res.ok) {
    if (contentType.includes('application/json')) {
      try {
        const body = JSON.parse(text)
        throw new Error(body.error || body.message || text)
      } catch (e) {
        if (e.message && e.message !== text) throw e
      }
    }
    throw new Error(text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() || `HTTP ${res.status}`)
  }
  if (!contentType.includes('application/json')) {
    const preview = text.slice(0, 120).replace(/\s+/g, ' ')
    throw new Error(`API ${path} 返回的不是 JSON，可能启动了旧版客户端或后端路由未更新：${preview}`)
  }
  return text ? JSON.parse(text) : {}
}

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="client-crash">
          <h1>界面渲染异常</h1>
          <p>{this.state.error?.message || String(this.state.error)}</p>
          <button onClick={() => window.location.reload()}>重新加载</button>
        </div>
      )
    }
    return this.props.children
  }
}

createRoot(document.getElementById('root')).render(<AppErrorBoundary><App /></AppErrorBoundary>)
