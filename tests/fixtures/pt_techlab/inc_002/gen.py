
import csv, random, hashlib
from datetime import datetime, timedelta
random.seed(42)
BASE = datetime(2026,8,17,6,0,0)
def T(m,s=0): return (BASE+timedelta(minutes=m,seconds=s)).strftime('%Y-%m-%dT%H:%M:%SZ')
def H(x): return hashlib.sha256(x.encode()).hexdigest()
hosts=["ws-%02d"%i for i in range(1,41)]+["dc-01","dc-02","build-srv-01","git-srv-01","file-srv-01","backup-01","scan-01"]
ip={h:"10.10.1.%d"%(i+10) for i,h in enumerate(hosts)}
ip.update({"build-srv-01":"10.10.3.5","git-srv-01":"10.10.3.6","dc-01":"10.10.1.10","scan-01":"10.10.9.9","file-srv-01":"10.10.3.7","backup-01":"10.10.3.8","dc-02":"10.10.1.11"})
users=["ivanov","petrova","sidorov","kuznetsov","orlova","admin_ops","svc_backup","svc_scan","svc_build","volkova","fedorov"]
edr=[];siem=[];ndr=[];ot=[]
c={"edr":0,"siem":0,"ndr":0,"ot":0}
def nid(k):
    c[k]+=1
    return "%s-%04d"%(k,c[k])

# ===== Цепочка INC-002: компрометация через фишинг -> CI/build =====
V=ip["ws-17"];U="smirnov";INC="INC-002"
C2="185.220.101.34";DOH="cdn-metrics.example-analytics.com"
BS="build-srv-01";BSIP=ip[BS];GS="git-srv-01";GSIP=ip[GS]
# Ф1 фишинг->запуск
edr.append([T(0),nid("edr"),"ws-17",U,"p-1000","p-0010","",H("outlook"),r"C:\Program Files\Microsoft Office\OUTLOOK.EXE","PROCESS_START",INC])
edr.append([T(1),nid("edr"),"ws-17",U,"p-1001","p-1000","",H("hta"),r"C:\Windows\System32\mshta.exe","PROCESS_START",INC])
edr.append([T(1,30),nid("edr"),"ws-17",U,"p-1002","p-1001",C2,H("ps1"),r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","PROCESS_START",INC])
edr.append([T(2),nid("edr"),"ws-17",U,"p-1003","p-1002","",H("drop"),r"C:\Users\smirnov\AppData\Local\Temp\invoice_viewer.exe","FILE_WRITE",INC])
edr.append([T(2,30),nid("edr"),"ws-17",U,"p-1004","p-1002",C2,H("drop"),r"C:\Users\smirnov\AppData\Local\Temp\invoice_viewer.exe","PROCESS_START",INC])
# Ф2 DoH туннель (NDR видит, SIEM почти нет)
for i in range(6):
    ndr.append([T(3+i*7),nid("ndr"),"ws-17",V,C2,"DoH","C2_SUSPECT",DOH,random.randint(900,4200),INC])
siem.append([T(4),nid("siem"),"ws-17",U,V,C2,"SUSPICIOUS_OUTBOUND","domain",DOH,INC])
# Ф3 kerberoasting + сервисная УЗ
edr.append([T(12),nid("edr"),"ws-17",U,"p-1005","p-1004","",H("rubeus"),r"C:\Users\smirnov\AppData\Local\Temp\svchosts.exe","PROCESS_START",INC])
for spn in ["MSSQLSvc/db01","HTTP/build-srv-01","CIFS/file-srv-01"]:
    siem.append([T(13),nid("siem"),"dc-01",U,V,ip["dc-01"],"KERBEROS_TGS_RC4","spn",spn,INC])
siem.append([T(14),nid("siem"),"dc-01","svc_build",V,ip["dc-01"],"LOGON_SERVICE_ACCOUNT_ANOMALY","account","svc_build",INC])

# Ф4 lateral movement на build-srv-01 под svc_build
ndr.append([T(15),nid("ndr"),"ws-17",V,BSIP,"SMB","LATERAL_SUSPECT","",random.randint(4000,9000),INC])
edr.append([T(16),nid("edr"),BS,"svc_build","p-2000","p-0020",V,H("wmiexec"),r"C:\Windows\System32\wbem\wmiprvse.exe","PROCESS_START",INC])
edr.append([T(16,30),nid("edr"),BS,"svc_build","p-2001","p-2000","",H("psh2"),r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","PROCESS_START",INC])
siem.append([T(17),nid("siem"),BS,"svc_build",V,BSIP,"REMOTE_EXEC_WMI","host",BS,INC])
# Ф5 доступ к репо + попытка подмены артефакта сборки (аналог OT-целостности)
ndr.append([T(20),nid("ndr"),BS,BSIP,GSIP,"HTTPS","ALLOWED","git-srv-01.corp.local",random.randint(2000,6000),INC])
edr.append([T(21),nid("edr"),BS,"svc_build","p-2002","p-2001","",H("gitclone"),r"C:\Program Files\Git\cmd\git.exe","PROCESS_START",INC])
edr.append([T(22),nid("edr"),BS,"svc_build","p-2003","p-2001","",H("artifact"),r"C:\ci\workspace\release\app-setup.msi","FILE_WRITE",INC])
# OT-слой заменён на CI-целостность: контроль хэша артефакта сборки
ot.append([T(23),nid("ot"),"artifact:app-setup.msi",BSIP,GSIP,"CI_PIPELINE","ARTIFACT_HASH_MISMATCH","build.integrity",128,INC])
ot.append([T(23,30),nid("ot"),"pipeline:release-prod",BSIP,GSIP,"CI_PIPELINE","UNSIGNED_ARTIFACT_PUSH","build.signing",96,INC])
siem.append([T(24),nid("siem"),BS,"svc_build",BSIP,GSIP,"CODE_REPO_WRITE_OFFHOURS","repo","release-prod",INC])

# ===== Отвлекающие фоновые аномалии (не INC-002) =====
# A) легитимный админ off-hours (похоже на атаку, но легитимно)
siem.append([T(30),nid("siem"),"dc-01","admin_ops",ip["dc-01"],ip["dc-02"],"REMOTE_EXEC_WMI","host","dc-02","BG-ADMIN"])
edr.append([T(30,20),nid("edr"),"dc-02","admin_ops","p-3000","p-0030","",H("padm"),r"C:\Windows\System32\wbem\wmiprvse.exe","PROCESS_START","BG-ADMIN"])
# B) сканер уязвимостей (шумит, но санкционирован)
for i in range(8):
    tgt=random.choice(hosts[:20])
    ndr.append([T(35+i,0),nid("ndr"),"scan-01",ip["scan-01"],ip[tgt],"TCP","SCAN_SUSPECT","",random.randint(60,300),"BG-SCAN"])
siem.append([T(36),nid("siem"),"scan-01","svc_scan",ip["scan-01"],"","VULN_SCAN_START","host","scan-01","BG-SCAN"])
# C) backup off-hours (легитимно)
siem.append([T(40),nid("siem"),"backup-01","svc_backup",ip["backup-01"],ip["file-srv-01"],"BACKUP_SUCCESS","host","file-srv-01","BG-BACKUP"])
ndr.append([T(40,10),nid("ndr"),"backup-01",ip["backup-01"],ip["file-srv-01"],"SMB","ALLOWED","",random.randint(50000,90000),"BG-BACKUP"])

# ===== Массовый доброкачественный фон (~1000 событий всего) =====
legit_img=[r"C:\Windows\System32\svchost.exe",r"C:\Windows\explorer.exe",r"C:\Program Files\Google\Chrome\chrome.exe",r"C:\Program Files\Microsoft Office\OUTLOOK.EXE",r"C:\Windows\System32\wbem\wmiprvse.exe",r"C:\Windows\System32\notepad.exe"]
legit_rule=["LOGON_SUCCESS","GPO_UPDATE","VPN_CONNECT","FIREWALL_ALLOW","AV_SCAN_COMPLETE","PASSWORD_CHANGE"]
legit_dns=["intranet.local","update.microsoft.com","crl.verisign.com","office365.com","ntp.corp.local","teams.microsoft.com"]
wsh=hosts[:40]
for _ in range(520):
    h=random.choice(wsh);u=random.choice(users[:6]);m=random.randint(0,45)
    edr.append([T(m,random.randint(0,59)),nid("edr"),h,u,"p-%d"%random.randint(4000,9000),"p-%d"%random.randint(10,99),"",H(random.choice(legit_img)+str(random.random())),random.choice(legit_img),"PROCESS_START","BACKGROUND"])
for _ in range(230):
    h=random.choice(wsh);u=random.choice(users[:6]);m=random.randint(0,45)
    siem.append([T(m,random.randint(0,59)),nid("siem"),h,u,ip[h],ip[random.choice(hosts)],random.choice(legit_rule),"host",h,"BACKGROUND"])
for _ in range(210):
    h=random.choice(wsh);m=random.randint(0,45)
    ndr.append([T(m,random.randint(0,59)),nid("ndr"),h,ip[h],ip[random.choice(hosts)],random.choice(["DNS","HTTPS","SMB","TCP"]),"ALLOWED",random.choice(legit_dns),random.randint(80,5000),"BACKGROUND"])
for _ in range(30):
    a=random.choice(["plc-01","plc-02","pipeline:nightly","artifact:agent.pkg"]);m=random.randint(0,45)
    ot.append([T(m,random.randint(0,59)),nid("ot"),a,ip["build-srv-01"],ip["git-srv-01"],"CI_PIPELINE",random.choice(["BUILD_OK","POLL","SIGN_OK"]),"build.ok",random.randint(40,120),"BACKGROUND"])
print("chain+bg built")

# ===== Фазы kill chain и техники MITRE ATT&CK для 27 событий цепочки =====
# Ключ — event_id: он детерминирован (nid считает по порядку), а цепочка пишется до фона,
# поэтому первые записи каждого источника принадлежат INC-002. Фоновые события фазы не
# получают намеренно: это не шаги атаки, и приписывать им фазу означало бы разметить шум.
#
# Набор фаз задан контрактом окна симуляции: recon, initial_access, execution, c2,
# privilege_escalation, lateral_movement, persistence, exfiltration, impact.
PHASES = {
    # Ф1 фишинг и запуск на рабочей станции
    "edr-0001": ("initial_access", "T1566.001"),   # вложение в почте
    "edr-0002": ("execution", "T1218.005"),        # mshta запускает нагрузку
    "edr-0003": ("execution", "T1059.001"),        # powershell с обращением к C2
    "edr-0004": ("execution", "T1204.002"),        # запись исполняемого файла
    "edr-0005": ("execution", "T1204.002"),        # запуск записанного файла
    # Ф2 управляющий канал по DoH
    "ndr-0001": ("c2", "T1071.004"),
    "ndr-0002": ("c2", "T1071.004"),
    "ndr-0003": ("c2", "T1071.004"),
    "ndr-0004": ("c2", "T1071.004"),
    "ndr-0005": ("c2", "T1071.004"),
    "ndr-0006": ("c2", "T1071.004"),
    "siem-0001": ("c2", "T1071.004"),              # SUSPICIOUS_OUTBOUND
    # Ф3 kerberoasting и захват служебной учётной записи
    "edr-0006": ("privilege_escalation", "T1558.003"),
    "siem-0002": ("privilege_escalation", "T1558.003"),
    "siem-0003": ("privilege_escalation", "T1558.003"),
    "siem-0004": ("privilege_escalation", "T1558.003"),
    "siem-0005": ("privilege_escalation", "T1078.002"),
    # Ф4 перемещение на сервер сборки
    "ndr-0007": ("lateral_movement", "T1021.002"),
    "edr-0007": ("lateral_movement", "T1047"),
    "edr-0008": ("execution", "T1059.001"),
    "siem-0006": ("lateral_movement", "T1047"),
    # Ф5 доступ к репозиторию и подмена артефакта сборки
    "ndr-0008": ("lateral_movement", "T1021"),
    "edr-0009": ("execution", "T1059"),
    "edr-0010": ("impact", "T1195.002"),
    "ot-0001": ("impact", "T1195.002"),
    "ot-0002": ("impact", "T1195.002"),
    "siem-0007": ("persistence", "T1195.002"),
}

# ===== Запись CSV в формате существующих фикстур =====
def wr(fn,header,rows):
    # Исходные строки не меняются: колонки фазы дописываются в копию, поэтому подсчёт
    # цепочки ниже по r[-1] продолжает читать incident_id.
    rows2=sorted(rows,key=lambda r:r[0])
    with open(fn,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);w.writerow([*header,"attack_phase","mitre_technique"])
        for r in rows2: w.writerow([*r,*PHASES.get(r[1],("",""))])
wr("edr.csv",["timestamp","event_id","hostname","username","process_guid","parent_process_guid","remote_ip","sha256","image_path","event_type","incident_id"],edr)
wr("siem.csv",["event_time","record_id","device_host","subject_user","src_ip","dst_ip","rule_name","indicator_type","indicator","incident_id"],siem)
wr("ndr.csv",["start_time","flow_id","src_host","src_ip","dst_ip","app_protocol","verdict","dns_query","bytes","incident_id"],ndr)
wr("ot.csv",["timestamp","event_id","asset_id","src_address","dst_address","protocol","operation","tag","payload_size","incident_id"],ot)
tot=len(edr)+len(siem)+len(ndr)+len(ot)
ch=sum(1 for L in (edr,siem,ndr,ot) for r in L if r[-1]=="INC-002")
print("edr=%d siem=%d ndr=%d ot=%d total=%d chain=%d"%(len(edr),len(siem),len(ndr),len(ot),tot,ch))
