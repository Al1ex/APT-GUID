## 项目介绍

整理APT领域的一些资料，涉及但不仅限于以下几个方面

- APT攻击工具

- APT分析报告

- APT攻击技巧

## 工具整理

#### 信息收集

##### 主动情报收集

- **EyeWitness**可以获取网站的屏幕快照，提供一些服务器信息，并在可能的情况下标识默认凭据 https://github.com/ChrisTruncer/EyeWitness
- **AWSBucketDump** 可用于快速枚举AWS S3 Buckets以寻找战利品的工具 https://github.com/jordanpotti/AWSBucketDump
- **AQUATONE**是用于对域名进行信息收集的工具 https://github.com/michenriksen/aquatone
- **Spoofcheck**，用于检查是否可以欺骗域名，该程序检查SPF和DMARC记录中是否存在允许欺骗的弱配置 https://github.com/BishopFox/spoofcheck
- **Nmap**用于发现计算机网络上的主机和服务 https://github.com/nmap/nmap
- **dnsrecon**是一个DNS枚举脚本 https://github.com/darkoperator/dnsrecon
- **dirsearch**是一个简单的命令行工具，爆破网站目录  https://github.com/maurosoria/dirsearch
- **Sn1per**是一个自动化渗透工具  https://github.com/1N3/Sn1per

##### 被动情报收集

- **Social Mapper** OSINT社交媒体映射工具，获取用户名和图像（或LinkedIn公司名称）列表，并在多个社交媒体网站上进行大规模的自动目标搜索。不受API限制，因为它使用了Selenium。 https://github.com/SpiderLabs/social_mapper
- **skiptracer** OSINT利用框架 https://github.com/xillwillx/skiptracer
- **FOCA**主要用于在扫描的文档中查找元数据和隐藏信息。 https://github.com/ElevenPaths/FOCA
- **theHarvester**用于从不同的公共来源收集子域名，电子邮件地址，虚拟主机，端口/banner和员工名称。 https://github.com/laramies/theHarvester
- **Metagoofil**是用于提取目标网站中可用的公共文档（pdf，doc，xls，ppt等）的元数据的工具。 https://github.com/laramies/metagoofil
- **SimplyEmail**电子邮件侦查。 https://github.com/killswitch-GUI/SimplyEmail
- **truffleHog**在git仓库中搜索敏感数据，深入挖掘提交历史和分支。 https://github.com/dxa4481/truffleHog
- **Just-Metadata** 收集和分析有关IP地址的元数据的工具。它尝试查找大型数据集中系统之间的关系。 https://github.com/ChrisTruncer/Just-Metadata
- typofinder 显示IP地址所在国家/地区。 https://github.com/nccgroup/typofinder
- **pwnedOrNot**是一个python脚本，用于检查电子邮件帐户是否因数据泄露而受到攻击；如果电子邮件帐户受到攻击，则它将继续查找该帐户的密码。 https://github.com/thewhiteh4t/pwnedOrNot
- **GitHarvester**该工具用于从GitHub收集信息，例如google dork。 https://github.com/metac0rtex/GitHarvester
- **pwndb**是一个python命令行工具，用于使用具有相同名称的Onion服务搜索泄漏的凭据。 https://github.com/davidtavarez/pwndb/
- **LinkedInt** LinkedIn Recon工具。 https://github.com/vysecurity/LinkedInt
- **CrossLinked** LinkedIn枚举工具，通过搜索引擎抓取从组织中提取有效的员工姓名。 https://github.com/m8r0wn/CrossLinked
- **findomain** 快速子域名枚举工具，它使用证书的透明性日志和一些API。 https://github.com/Edu4rdSHL/findomain

#### 漏洞利用

- **WinRAR Remote Code Execution** Proof of Concept exploit for CVE-2018-20250. https://github.com/WyAtu/CVE-2018-20250
- **Composite Moniker** Proof of Concept exploit for CVE-2017-8570. https://github.com/rxwx/CVE-2017-8570
- **Exploit toolkit CVE-2017-8759** https://github.com/bhdresh/CVE-2017-8759
- **CVE-2017-11882 Exploit** https://github.com/unamer/CVE-2017-11882
- **Adobe Flash Exploit CVE-2018-4878**. https://github.com/anbai-inc/CVE-2018-4878
- **Exploit toolkit CVE-2017-0199**是一个方便的python脚本，为渗透测试人员和安全研究人员提供了一种快速有效的方法来测试Microsoft Office RCE。https://github.com/bhdresh/CVE-2017-0199
- **demiguise** HTA加密工具 https://github.com/nccgroup/demiguise
- **Office-DDE-Payloads**收集脚本和模板，生成嵌入了DDE（无宏命令执行技术）的Office文档。https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads
- **CACTUSTORCH**用于对手模拟的payload生成。https://github.com/mdsecactivebreach/CACTUSTORCH
- **SharpShooter**是一个payload创建框架，用于执行任意CSharp源代码。https://github.com/mdsecactivebreach/SharpShooter
- **DKMC**，这是一种生成混淆的shellcode的工具，该shellcode存储在图像中。该映像是100％有效的，也是100％有效的shellcode。https://github.com/Mr-Un1k0d3r/DKMC
- **恶意宏生成器**用于生成模糊的宏，其中还包括AV/沙箱转义机制。https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator
- **SCT-obfuscator** Cobalt Strike SCT payload混淆器。https://github.com/Mr-Un1k0d3r/SCT-obfuscator
- **Invoke-Obfuscation** PowerShell混淆器。https://github.com/danielbohannon/Invoke-Obfuscation
- **Invoke-CradleCrafter** PowerShell远程下载的生成器和混淆器。https://github.com/danielbohannon/Invoke-CradleCrafter
- **Invoke-DOSfuscation** cmd.exe命令混淆生成器和检测测试工具。https://github.com/danielbohannon/Invoke-DOSfuscation
- **morphHTA**。https://github.com/vysec/morphHTA
- **Unicorn**是使用PowerShell降级攻击并将shellcode直接注入内存的简单工具。https://github.com/trustedsec/unicorn
- **Shellter**是一种动态的Shellcode注入工具，也是有史以来第一个真正的动态PE感染器。https://www.shellterproject.com/
- **EmbedInHTML**嵌入和隐藏HTML中的任何文件。https://github.com/Arno0x/EmbedInHTML
- **SigThief**窃取签名并制作一个无效签名。https://github.com/secretsquirrel/SigThief
- **Veil**，https://github.com/Veil-Framework/Veil
- **CheckPlease**用PowerShell，Python，Go，Ruby，C，C＃，Perl和Rust编写的 Sandbox逃避模块。https://github.com/Arvanaghi/CheckPlease
- **Invoke-PSImage**是一种将PowerShell脚本嵌入PNG文件的像素中并可以执行的工具。https://github.com/peewpw/Invoke-PSImage
- **LuckyStrike**基于PowerShell的实用程序，用于创建恶意Office宏文档。仅用于渗透或教育目的。https://github.com/curi0usJack/luckystrike
- **ClickOnceGenerator** https://github.com/Mr-Un1k0d3r/ClickOnceGenerator
- **macro_pack**是@EmericNasi的工具，用于自动混淆和生成MS Office文档，VB脚本以及其他格式的渗透测试，演示和社会工程评估。https://github.com/sevagas/macro_pack
- **StarFighters**一个基于JavaScript和VBScript的Empire Launcher。https://github.com/Cn33liz/StarFighters
- **nps_payload** 该脚本将生成payload，以避免基本的入侵检测。它利用了来自多个不同来源的公开展示的技术。https://github.com/trustedsec/nps_payload
- **SocialEngineeringPay**加载了一系列用于凭据盗窃和鱼叉式网络钓鱼攻击的社交工程技巧和payload。https://github.com/bhdresh/SocialEngineeringPayloads
- **Social-Engineer Toolkit**是一个为社会工程设计的开源渗透测试框架。https://github.com/trustedsec/social-engineer-toolkit
- **phishery**是一个简单的启用SSL的HTTP服务器，其主要目的是通过基本身份验证来进行网络钓鱼凭据。 https://github.com/ryhanson/phishery
- **PowerShdll**与rundll32 一起运行PowerShell。绕过软件限制。https://github.com/p3nt4/PowerShdll
- **UltimateAppLockerByPassList**记录绕过AppLocker的最常用技术。https://github.com/api0cradle/UltimateAppLockerByPassList
- **ruler**，可让您通过MAPI / HTTP或RPC / HTTP协议与Exchange服务器进行远程交互。https://github.com/sensepost/ruler
- **Generate-Macro**是一个独立的PowerShell脚本，它将生成具有指定payload和持久性方法的恶意Microsoft Office文档。https://github.com/enigma0x3/Generate-Macro
- **MaliciousMacroMSBuild**生成恶意宏并通过MSBuild应用程序白名单绕过执行Powershell或Shellcode。https://github.com/infosecn1nja/MaliciousMacroMSBuild
- **Meta Twin** 文件资源克隆器。从一个文件中提取包括数字签名在内的元数据，然后将其注入另一个文件中。https://github.com/threatexpress/metatwin
- **WePWNise**生成独立于体系结构的VBA代码，以在Office文档或模板中使用，并自动绕过应用程序控制。https://github.com/mwrlabs/wePWNise
- **DotNetToJScript**，用于创建一个JScript文件，该文件从内存中加载.NET v2程序集。https://github.com/tyranid/DotNetToJScript
- **PSAmsi**是用于审核和破坏AMSI签名的工具。https://github.com/cobbr/PSAmsi
- **ReflectiveDLLInjection** https://github.com/stephenfewer/ReflectiveDLLInjection
- **ps1encode**用于生成和编码基于powershell的metasploit payload。https://github.com/CroweCybersecurity/ps1encode
- **Worse-PDF**。用于从Windows机器上窃取Net-NTLM哈希。https://github.com/3gstudent/Worse-PDF
- **SpookFlare**具有绕过安全措施的不同角度。https://github.com/hlldz/SpookFlare
- **GreatSCT**是一个开源项目，用于生成应用程序白名单绕过。https://github.com/GreatSCT/GreatSCT
- **NPS**在没有Powershell的情况下运行Powershell。https://github.com/Ben0xA/nps
- **Meterpreter_Paranoid_Mode.sh** 保护Meterpreter的分阶段/无阶段连接。https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL
- **backdoor-factory**（BDF）将使用用户所需的shellcode修补可执行二进制文件，并继续正常执行预修补状态。https://github.com/secretsquirrel/the-backdoor-factory
- **MacroShop**脚本集合，以帮助通过Office宏传递payload。https://github.com/khr0x40sh/MacroShop
- **UnmanagedPowerShell**从非托管进程执行PowerShell。https://github.com/leechristensen/UnmanagedPowerShell
- **evil-ssdp Spoof** SSDP会针对网络上的NTLM哈希回复网络钓鱼。创建一个伪造的UPNP设备，诱使用户访问恶意网页仿冒页面。https://gitlab.com/initstring/evil-ssdp
- **Ebowla**用于制作环境关键payload的框架。https://github.com/Genetic-Malware/Ebowla
- **make-pdf**嵌入式工具可用于创建带有嵌入式文件的PDF文档。https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py
- **avet**（AntiVirusEvasionTool）使用不同的规避技术将Windows机器定位为具有可执行文件的计算机。https://github.com/govolution/avet
- **EvilClippy**用于创建恶意MS Office文档的跨平台助手。可以隐藏VBA宏，混淆宏。在Linux，OSX和Windows上运行。https://github.com/outflanknl/EvilClippy
- **CallObfuscator**从静态分析工具和调试器中混淆Windows API。https://github.com/d35ha/CallObfuscator
- **Donut**是一个Shellcode生成工具，可从.NET程序集创建与位置无关的Shellcodepayload。此shellcode可用于将Assembly注入到任意Windows进程中。https://github.com/TheWover/donut

#### 社工钓鱼

- **King Phisher** https://github.com/securestate/king-phisher
- **FiercePhish** https://github.com/Raikia/FiercePhish
- **ReelPhish** https://github.com/fireeye/ReelPhish/
- **Gophish** https://github.com/gophish/gophish
- **CredSniper** https://github.com/ustayready/CredSniper
- **PwnAuth** https://github.com/fireeye/PwnAuth
- **Phishing Frenzy** https://github.com/pentestgeek/phishing-frenzy
- **Phishing Pretexts** https://github.com/L4bF0x/PhishingPretexts
- **Modlishka** https://github.com/drk1wi/Modlishka
- **Evilginx2** https://github.com/kgretzky/evilginx2

#### C2框架

- **Cobalt Strike** https://cobaltstrike.com/
- **Empire** https://github.com/EmpireProject/Empire
- **Metasploit Framework** https://github.com/rapid7/metasploit-framework
- **SILENTTRINITY** https://github.com/byt3bl33d3r/SILENTTRINITY
- **Pupy** https://github.com/n1nj4sec/pupy
- **Koadic** https://github.com/zerosum0x0/koadic
- **PoshC2** https://github.com/nettitude/PoshC2_Python
- **Gcat** https://github.com/byt3bl33d3r/gcat
- **TrevorC2** https://github.com/trustedsec/trevorc2
- **Merlin** https://github.com/Ne0nd0g/merlin
- **Quasar** https://github.com/quasar/QuasarRAT
- **Covenant** https://github.com/cobbr/Covenant
- **FactionC2** https://github.com/FactionC2/
- **DNScat2** https://github.com/iagox86/dnscat2
- **Sliver** https://github.com/BishopFox/sliver
- **EvilOSX** https://github.com/Marten4n6/EvilOSX
- **EggShell** https://github.com/neoneggplant/EggShell

- **Rapid Attack Infrastructure (RAI)** 红队基础设施工具集 https://github.com/obscuritylabs/RAI
- **Red Baron** https://github.com/byt3bl33d3r/Red-Baron
- **EvilURL** 为IDN同形文字攻击生成unicode邪恶的域名并对其进行检测. https://github.com/UndeadSec/EvilURL
- **Domain Hunter** 检查过期的域名，bluecoat分类和Archive.org历史记录，以确定网络钓鱼和C2域名的最佳选择。https://github.com/threatexpress/domainhunter
- **PowerDNS** https://github.com/mdsecactivebreach/PowerDNS
- **Chameleon** 逃避代理分类的工具。 https://github.com/mdsecactivebreach/Chameleon
- **CatMyFish** https://github.com/Mr-Un1k0d3r/CatMyFish
- **Malleable C2** C2 Profiles https://github.com/rsmudge/Malleable-C2-Profiles
- **Malleable-C2-Randomizer** https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
- **FindFrontableDomains** 搜索潜在的可扩展域。 https://github.com/rvrsh3ll/FindFrontableDomains
- **Postfix-Server-Setup** 快速建立钓鱼服务器 https://github.com/n0pe-sled/Postfix-Server-Setup
- **DomainFrontingLists** 可用的CDN前置域名列表https://github.com/vysec/DomainFrontingLists
- **Apache2-Mod-Rewrite-Setup** C2重定向 https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup
- **mod_rewrite rule** 规避沙盒 https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
- **external_c2 framework** python写的External C2. https://github.com/Und3rf10w/external_c2_framework
- **Malleable-C2-Profiles** https://www.cobaltstrike.com/. https://github.com/xx0hcd/Malleable-C2-Profiles
- **ExternalC2** https://github.com/ryhanson/ExternalC2
- **cs2modrewrite** https://github.com/threatexpress/cs2modrewrite
- **e2modrewrite** https://github.com/infosecn1nja/e2modrewrite
- **redi** 设置 CobaltStrike 重定向https://github.com/taherio/redi
- **cat-sites** 用于分类的站点库。 https://github.com/audrummer15/cat-sites
- **ycsm** 快速设置nginx反向代理 https://github.com/infosecn1nja/ycsm
- **Domain Fronting Google App Engine**. https://github.com/redteam-cyberark/Google-Domain-fronting
- **DomainFrontDiscover** https://github.com/peewpw/DomainFrontDiscover
- **Automated Empire Infrastructure** https://github.com/bneg/RedTeam-Automation
- **Serving Random Payloads** with NGINX. https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9
- **meek** https://github.com/arlolra/meek
- **CobaltStrike-ToolKit** CS脚本 https://github.com/killswitch-GUI/CobaltStrike-ToolKit
- **mkhtaccess_red** 自动生成HTaccess进行payload传递-自动从以前见过的沙盒公司/源中提取ips / nets等，并将其重定向到良性的payload。https://github.com/violentlydave/mkhtaccess_red
- **RedFile** Payload 服务 https://github.com/outflanknl/RedFile
- **keyserver** https://github.com/leoloobeek/keyserver
- **DoHC2** https://github.com/SpiderLabs/DoHC2
- **HTran** https://github.com/HiwinCN/HTran

#### 后续渗透

- **CrackMapExec** https://github.com/byt3bl33d3r/CrackMapExec
- **PowerLessShell** https://github.com/Mr-Un1k0d3r/PowerLessShell
- **GoFetch** 自动执行BloodHound生成攻击计划。
  https://github.com/GoFetchAD/GoFetch
- **ANGRYPUPPY** CobaltStrike中的bloodhound攻击路径自动化。 https://github.com/vysec/ANGRYPUPPY
- **DeathStar** https://github.com/byt3bl33d3r/DeathStar
- **SharpHound** https://github.com/BloodHoundAD/SharpHound
- **BloodHound.py** 是基于Impacket的基于Python的BloodHound ingestor。 https://github.com/fox-it/BloodHound.py
- **Responder** 中间人攻击工具 https://github.com/SpiderLabs/Responder
- **SessionGopher** 是一个PowerShell工具，使用WMI为远程访问工具（如WinSCP，PuTTY，SuperPuTTY，FileZilla和Microsoft远程桌面）提取保存的会话信息。 https://github.com/fireeye/SessionGopher
- **PowerSploit** pwsh工具集 https://github.com/PowerShellMafia/PowerSploit
- **Nishang** https://github.com/samratashok/nishang
- **Inveigh** 中间人攻击工具 https://github.com/Kevin-Robertson/Inveigh
- **PowerUpSQL** a PowerShell Toolkit for Attacking SQL Server. https://github.com/NetSPI/PowerUpSQL
- **MailSniper** https://github.com/dafthack/MailSniper
- **DomainPasswordSpray** https://github.com/dafthack/DomainPasswordSpray
- **WMIOps** https://github.com/ChrisTruncer/WMIOps
- **Mimikatz** https://github.com/gentilkiwi/mimikatz
- **LaZagne** https://github.com/AlessandroZ/LaZagne
- **mimipenguin** 抓取linux密码 https://github.com/huntergregal/mimipenguin
- **PsExec** https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
- **KeeThief** https://github.com/HarmJ0y/KeeThief
- **PSAttack** https://github.com/jaredhaight/PSAttack
- **Internal Monologue Attack** 无需接触LSASS即可检索NTLM哈希值。https://github.com/eladshamir/Internal-Monologue
- **Impacket** python工具包 https://github.com/CoreSecurity/impacket
- **icebreaker** 如果您位于内部网络上但不在AD环境中，则将获取纯文本Active Directory凭据。 https://github.com/DanMcInerney/icebreaker
- **Living Off The Land Binaries and Scripts (and now also Libraries)**https://github.com/api0cradle/LOLBAS
- **WSUSpendu** https://github.com/AlsidOfficial/WSUSpendu
- **Evilgrade** https://github.com/infobyte/evilgrade
- **NetRipper** 针对Windows系统的后渗透工具，该工具使用API hook来拦截低特权用户的网络流量和与加密相关的功能，从而能够在加密之前/解密之后捕获纯文本流量和加密流量。https://github.com/NytroRST/NetRipper
- **LethalHTA** Lateral Movement technique using DCOM and HTA. https://github.com/codewhitesec/LethalHTA
- **Invoke-PowerThIEf** https://github.com/nettitude/Invoke-PowerThIEf
- **RedSnarf** https://github.com/nccgroup/redsnarf
- **HoneypotBuster** 为红队设计的Microsoft PowerShell模块，可用于在网络或主机中查找蜜罐和令牌。 https://github.com/JavelinNetworks/HoneypotBuster
- **PAExec** 在远程Windows计算机上启动Windows程序，而无需先在远程计算机上安装软件。 https://www.poweradmin.com/paexec/

#### 网络代理

- **Tunna** 用来绕过防火墙环境中的网络限制 https://github.com/SECFORCE/Tunna
- **reGeorg** socks代理工具 https://github.com/sensepost/reGeorg
- **Blade** Webshell 管理工具 https://github.com/wonderqs/Blade
- **TinyShell** Web Shell 框架. https://github.com/threatexpress/tinyshell
- **PowerLurk** 用于构建恶意WMI PowerShell工具集. https://github.com/Sw4mpf0x/PowerLurk
- **DAMP** 通过基于主机的安全描述符修改实现持久性
  https://github.com/HarmJ0y/DAMP

#### 权限提升

##### 域内提权

- **PowerView** https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- **Get-GPPPassword** https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
- **Invoke-ACLpwn** https://github.com/fox-it/Invoke-ACLPwn
- **BloodHound** https://github.com/BloodHoundAD/BloodHound
- **PyKEK** https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
- **Grouper** 自动寻找组策略漏洞的工具
  https://github.com/l0ss/Grouper
- **ADRecon** https://github.com/sense-of-security/ADRecon
- **ADACLScanner** https://github.com/canix1/ADACLScanner
- **ACLight** 用于发现可以作为目标的域特权帐户-包括Shadow Admins。https://github.com/cyberark/ACLight
- **LAPSToolkit** https://github.com/leoloobeek/LAPSToolkit
- **PingCastle** https://www.pingcastle.com/download
- **RiskySPNs**是PowerShell脚本的集合，专注于检测和查询SPN（服务主体名称）关联的帐户。 https://github.com/cyberark/RiskySPN
- **Mystique** 是一个可与Kerberos S4U扩展配合使用的PowerShell工具，此模块可通过将KCD与协议转换结合使用，协助蓝队识别危险的Kerberos委派配置，以及红队模拟任何用户。 https://github.com/machosec/Mystique
- **Rubeus** https://github.com/GhostPack/Rubeus
- **kekeo** https://github.com/gentilkiwi/kekeo

##### Linux提权

- https://github.com/Al1ex/Heptagram/tree/master/Linux/Elevation Linux提权收集
- https://github.com/AlessandroZ/BeRoot py,通过检查常见的错误配置来查找提权方法. 支持Windows/Linux/Mac
- https://github.com/mschwager/0wned 利用python包进行高权限用户创建
- https://github.com/mzet-/linux-exploit-suggester 查找linux有哪些补丁没有打的脚本
- https://github.com/belane/linux-soft-exploit-suggester 查找linux有哪些有漏洞的软件
- https://github.com/dirtycow/dirtycow.github.io 脏牛提权漏洞exp
- https://github.com/FireFart/dirtycow 脏牛提权漏洞exp
- https://github.com/stanleyb0y/sushell 利用su小偷实现低权限用户窃取root用户口令
- https://github.com/jas502n/CVE-2018-17182/ Linux 内核VMA-UAF 提权漏洞 CVE-2018-17182
- https://github.com/jas502n/CVE-2018-14665 CVE-2018-14665，linux下Xorg X服务器提权利用
- https://github.com/nmulasmajic/syscall_exploit_CVE-2018-8897 Linux系统利用Syscall实现提权
- https://github.com/can1357/CVE-2018-8897 Linux系统利用Syscall实现提权
- https://github.com/SecWiki/linux-kernel-exploits linux-kernel-exploits Linux平台提权漏洞集合
- https://github.com/nilotpalbiswas/Auto-Root-Exploit linux自动提权脚本
- https://github.com/WazeHell/PE-Linux Linux提权工具
- https://guif.re/linuxeop linux提权命令集合

##### Windows提权

- https://github.com/Al1ex/Heptagram/tree/master/Windows/Elevation Windows提权收集
- http://www.fuzzysecurity.com/tutorials/16.html windows平台教程级提权参考文章
- https://github.com/SecWiki/windows-kernel-exploits Windows平台提权漏洞Exp集合
- https://github.com/51x/WHP windows下各种提权与利用工具
- https://github.com/rasta-mouse/Sherlock win提权漏洞验证
- https://github.com/WindowsExploits/Exploits 微软CVE-2012-0217、CVE-2016-3309、CVE-2016-3371、CVE-2016-7255、CVE-2017-0213提权利用
- https://github.com/decoder-it/lonelypotato RottenPotatoNG变种，利用NBNS本地域名欺骗和WPAD代理欺骗提权
- https://github.com/ohpe/juicy-potato RottenPotatoNG变种，利用com对象、用户token进行提权
- https://github.com/foxglovesec/Potato RottenPotatoNG变种，利用本地域名欺骗和代理欺骗提权
- https://github.com/DanMcInerney/icebreaker 处于内网环境但又在AD环境之外，icebreaker将会帮助你获取明文Active Directory凭据（活动目录存储在域控服务器可用于提权）
- https://github.com/hausec/ADAPE-Script Active Directory权限提升脚本
- https://github.com/klionsec/BypassAV-AllThings 利用aspx一句话配合提权payload提权
- https://github.com/St0rn/Windows-10-Exploit msf插件，win10 uac bypass
- https://github.com/sam-b/CVE-2014-4113 利用Win32k.sys内核漏洞进行提取，ms14-058
- https://github.com/breenmachine/RottenPotatoNG 利用NBNS本地域名欺骗和WPAD代理欺骗提权
- https://github.com/unamer/CVE-2018-8120 影响Win32k组件，针对win7和win2008提权
- https://github.com/alpha1ab/CVE-2018-8120 在win7与win2k8的基础上增加了winXP与win2k3
- https://github.com/0xbadjuju/Tokenvator 使用Windows令牌提升权限的工具，提供一个交互命令行界面

#### 数据过滤

- **CloakifyFactory** & the Cloakify Toolset - https://github.com/TryCatchHCF/Cloakify
- **DET** (is provided AS IS), 是在同一时间使用单个或多个通道执行数据渗透的POC。 https://github.com/sensepost/DET
- **DNSExfiltrator** . https://github.com/Arno0x/DNSExfiltrator
- **PyExfil** a Python Package for Data Exfiltration. https://github.com/ytisf/PyExfil
- **Egress-Assess** 是用于测试出口数据检测功能的工具。 https://github.com/ChrisTruncer/Egress-Assess
- **Powershell RAT** 基于python的后门程序，使用Gmail将数据作为电子邮件附件传输。https://github.com/Viralmaniar/Powershell-RAT

#### Other

##### 对手模拟

- **MITRE CALDERA** 模拟入侵者的攻击手法,并进行分析 https://github.com/mitre/caldera
- **APTSimulator** https://github.com/NextronSystems/APTSimulator
- **Atomic Red Team** - https://github.com/redcanaryco/atomic-red-team
- **Network Flight Simulator** https://github.com/alphasoc/flightsim
- **Metta** - https://github.com/uber-common/metta
- **Red Team Automation (RTA)** - RTA提供了一个脚本框架，该脚本让蓝队可以根据MITER ATT＆CK进行建模，针对恶意工具测试其检测能力。 https://github.com/endgameinc/RTA

##### 无线攻击

- **Wifiphisher** WIFI自动关联攻击工具. https://github.com/wifiphisher/wifiphisher
- **mana** 中间人攻击. https://github.com/sensepost/mana

##### 嵌入式攻击

- **magspoof** https://github.com/samyk/magspoof
- **WarBerryPi** https://github.com/secgroundzero/warberry
- **P4wnP1** https://github.com/mame82/P4wnP1
- **malusb** https://github.com/ebursztein/malusb
- **Fenrir** https://github.com/Orange-Cyberdefense/fenrir-ocd
- **poisontap** https://github.com/samyk/poisontap
- **WHID**
  https://github.com/whid-injector/WHID
- **PhanTap** https://github.com/nccgroup/phantap

##### 通信隐匿

- **RocketChat** [https://rocket.chat](https://rocket.chat/)
- **Etherpad** https://etherpad.org/

##### 日志整理

- **RedELK** https://github.com/outflanknl/RedELK/
- **CobaltSplunk** https://github.com/vysec/CobaltSplunk
- **Red Team Telemetry** https://github.com/ztgrace/red_team_telemetry
- **Elastic for Red Teaming** https://github.com/SecurityRiskAdvisors/RedTeamSIEM
- **Ghostwriter** https://github.com/GhostManager/Ghostwriter

##### C#武器化

- **SharpSploit** .NET后渗透框架 https://github.com/cobbr/SharpSploit
- **GhostPack** Csharp工具集 https://github.com/GhostPack
- **SharpWeb** 读取常见浏览器密码 https://github.com/djhohnstein/SharpWeb
- **reconerator** https://github.com/stufus/reconerator
- **SharpView** C#版PowerView. https://github.com/tevora-threat/SharpView
- **Watson** https://github.com/rasta-mouse/Watson

##### LABS

- **Detection Lab** 自动化建立一个lab https://github.com/clong/DetectionLab ---五星推荐
- **Modern Windows Attacks and Defense Lab**https://github.com/jaredhaight/WindowsAttackAndDefenseLab
- **Invoke-UserSimulator** https://github.com/ubeeri/Invoke-UserSimulator
- **Invoke-ADLabDeployer** 自动化部署AD环境 https://github.com/outflanknl/Invoke-ADLabDeployer
- **Sheepl** https://github.com/SpiderLabs/sheepl

##### Script

###### Aggressor Scripts

- https://github.com/invokethreatguy/CSASC
- https://github.com/secgroundzero/CS-Aggressor-Scripts
- https://github.com/Und3rf10w/Aggressor-scripts
- https://github.com/harleyQu1nn/AggressorScripts
- https://github.com/rasta-mouse/Aggressor-Script
- https://github.com/RhinoSecurityLabs/Aggressor-Scripts
- https://github.com/bluscreenofjeff/AggressorScripts
- https://github.com/001SPARTaN/aggressor_scripts
- https://github.com/360-A-Team/CobaltStrike-Toolset
- https://github.com/FortyNorthSecurity/AggressorAssessor
- https://github.com/ramen0x3f/AggressorScripts

###### Red-Team

- https://github.com/FuzzySecurity/PowerShell-Suite
- https://github.com/nettitude/Powershell
- https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts
- https://github.com/threatexpress/red-team-scripts
- https://github.com/SadProcessor/SomeStuff
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts
- https://github.com/enigma0x3/Misc-PowerShell-Stuff
- https://github.com/ChrisTruncer/PenTestScripts
- https://github.com/bluscreenofjeff/Scripts
- https://github.com/xorrior/RandomPS-Scripts
- https://github.com/xorrior/Random-CSharpTools
- https://github.com/leechristensen/Random
- https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/social-engineering