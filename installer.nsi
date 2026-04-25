!include "MUI2.nsh"

Name "GHOSTLINK"
OutFile "GHOSTLINK_Setup.exe"
InstallDir "$PROGRAMFILES\GHOSTLINK"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "dist\GHOSTLINK\*.*"
  
  ;   Tell NSIS to install shortcuts for ALL users
  SetShellVarContext all
  
  CreateShortCut "$DESKTOP\GHOSTLINK.lnk" "$INSTDIR\GHOSTLINK.exe"
  CreateDirectory "$SMPROGRAMS\GHOSTLINK"
  CreateShortCut "$SMPROGRAMS\GHOSTLINK\GHOSTLINK.lnk" "$INSTDIR\GHOSTLINK.exe"
  CreateShortCut "$SMPROGRAMS\GHOSTLINK\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK" "DisplayName" "GHOSTLINK"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK" "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$INSTDIR\*.*"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\GHOSTLINK.lnk"
  RMDir /r "$SMPROGRAMS\GHOSTLINK"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK"
SectionEnd