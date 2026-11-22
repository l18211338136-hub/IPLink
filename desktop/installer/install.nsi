; IP Link Windows installer (NSIS)
; Build: makensis install.nsi
; The GUI binary is a single file (frontend embedded), so no extra files are needed.

Unicode true

Name "IP Link"
OutFile "..\..\bin\IPLink-Setup.exe"
InstallDir "$LOCALAPPDATA\Programs\IPLink"
InstallDirRegKey HKCU "Software\IPLink" "InstallDir"
RequestExecutionLevel user

!define APP_NAME "IP Link"
!define APP_EXE "iplink-desktop.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\IPLink"
!ifndef IPLINK_EXE
  !define IPLINK_EXE "..\..\bin\iplink-desktop.exe"
!endif

Page Directory
Page InstFiles
UninstPage UninstConfirm
UninstPage InstFiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "${IPLINK_EXE}"

  ; Persist install dir for uninstall / upgrade.
  WriteRegStr HKCU "Software\IPLink" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "IP Link"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start menu + desktop shortcut.
  CreateDirectory "$SMPROGRAMS\IP Link"
  CreateShortcut "$SMPROGRAMS\IP Link\IP Link.lnk" "$INSTDIR\${APP_EXE}"
  CreateShortcut "$DESKTOP\IP Link.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\IP Link\IP Link.lnk"
  RMDir "$SMPROGRAMS\IP Link"
  Delete "$DESKTOP\IP Link.lnk"
  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "Software\IPLink"
SectionEnd
