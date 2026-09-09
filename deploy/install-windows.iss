; ============================================================
;  Robin Client Monitor - Instalador Windows (Inno Setup) §16
;
;  Compilar:
;    1) Inno Setup (https://jrsoftware.org/isinfo.php)
;    2) nssm.exe junto a este .iss
;    3) robin-client-monitor.exe (dist/) junto a este .iss
;    4) config_client.json (plantilla packaged o preconfigurada)
;
;  Silencioso (SCCM / Intune / GPO):
;    robin-client-monitor-setup.exe /VERYSILENT /NORESTART ^
;      /ENROLL=TOKEN /ENROLLSERVER=https://host:8000 /ENROLLTENANT=t1
;
;  ARM64: compilá el .exe en un host arm64 y usá el mismo .iss
;  (ArchitecturesAllowed incluye arm64).
;
;  Firma Authenticode: deploy/sign-windows.ps1 (CI, no en el repo).
; ============================================================

[Setup]
AppName=Robin Client Monitor
AppVersion=0.9.0
AppPublisher=Ruvic Colsoft
AppPublisherURL=https://ruvic.xyz
DefaultDirName={autopf}\robin-client-monitor
DefaultGroupName=Robin Client Monitor
OutputDir=..\dist
OutputBaseFilename=robin-client-monitor-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible arm64
ArchitecturesInstallIn64BitMode=x64compatible arm64
UninstallDisplayName=Robin Client Monitor
UninstallDisplayIcon={app}\robin-client-monitor.exe
; Permite /DIR= y parámetros /ENROLL= desde msiexec-equivalente de Inno
DisableWelcomePage=no
MinVersion=10.0
SetupLogging=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "robin-client-monitor.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "config_client.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist skipifsourcedoesntexist
Source: "config_client.packaged.json"; DestDir: "{app}"; DestName: "config_client.json"; Flags: ignoreversion onlyifdoesntexist skipifsourcedoesntexist
Source: "enrollment\*"; DestDir: "{app}\enrollment"; Flags: ignoreversion recursesubdirs onlyifdoesntexist skipifsourcedoesntexist
Source: "nssm.exe"; DestDir: "{app}\nssm"; Flags: ignoreversion

[Code]
function EnrollToken: String;
begin
  Result := ExpandConstant('{param:ENROLL}');
  if Result = '' then
    Result := GetEnv('ENROLLTOKEN');
end;

function NeedEnroll: Boolean;
begin
  Result := EnrollToken <> '';
end;

function EnrollParams(Param: String): String;
var
  S, Server, Tenant, Name: String;
begin
  S := '--enroll "' + EnrollToken + '"';
  Server := ExpandConstant('{param:ENROLLSERVER}');
  if Server = '' then Server := GetEnv('ENROLLSERVER');
  Tenant := ExpandConstant('{param:ENROLLTENANT}');
  if Tenant = '' then Tenant := GetEnv('ENROLLTENANT');
  Name := ExpandConstant('{param:ENROLLNAME}');
  if Name = '' then Name := GetEnv('ENROLLNAME');
  if Server <> '' then S := S + ' --enroll-server "' + Server + '"';
  if Tenant <> '' then S := S + ' --enroll-tenant "' + Tenant + '"';
  if Name <> '' then S := S + ' --enroll-name "' + Name + '"';
  if (ExpandConstant('{param:ENROLLINSECURE}') = '1') or (GetEnv('ENROLLINSECURE') = '1') then
    S := S + ' --enroll-insecure';
  Result := S;
end;

[Run]
; Enrollment opcional (token de un solo uso) ANTES de registrar el servicio
Filename: "{app}\robin-client-monitor.exe"; Parameters: "{code:EnrollParams}"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; Check: NeedEnroll; StatusMsg: "Enrollment del agente..."
Filename: "{app}\nssm\nssm.exe"; Parameters: "install robin-client-monitor ""{app}\robin-client-monitor.exe"""; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor AppParameters ""--max-retries -1 --retry-delay 2"""; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor AppDirectory ""{app}"""; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor AppExit Default Restart"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor AppRestartDelay 3000"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor Start SERVICE_AUTO_START"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "set robin-client-monitor DisplayName ""Robin Client Monitor"""; Flags: runhidden waituntilterminated
Filename: "{app}\nssm\nssm.exe"; Parameters: "start robin-client-monitor"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "failure robin-client-monitor reset= 86400 actions= restart/3000/restart/10000/restart/30000"; Flags: runhidden
Filename: "sc.exe"; Parameters: "failureflag robin-client-monitor 1"; Flags: runhidden
Filename: "{app}\robin-client-monitor.exe"; Parameters: "--self-test"; Flags: runhidden

[UninstallRun]
Filename: "{app}\nssm\nssm.exe"; Parameters: "stop robin-client-monitor"; Flags: runhidden
Filename: "{app}\nssm\nssm.exe"; Parameters: "remove robin-client-monitor confirm"; Flags: runhidden
