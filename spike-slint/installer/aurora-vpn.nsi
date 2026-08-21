; Установщик Aurora VPN.
;
; Ставит в ту же папку и заводит ту же запись в списке программ, что и прежняя
; сборка на WebView2, — поэтому кладётся поверх неё как обновление, а не второй
; копией рядом. Прежний uninstall.exe перезаписывается нашим.
;
; Флаги командной строки те же, что понимает встроенное обновление приложения
; (api.rs, install_update): /S — без окон, /UPDATE — не трогать ярлыки, /R —
; запустить приложение после установки.

Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SOURCE
  !error "SOURCE не задан: нужен путь к папке с готовыми файлами"
!endif

!define APP_NAME "Aurora VPN"
!define APP_EXE "aurora-vpn.exe"
!define PUBLISHER "aurora"
; Имя ключа то же, что у прежней сборки, — иначе в «Установке и удалении
; программ» появилась бы вторая строка вместо обновления первой.
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
!define AUTOSTART_TASK "Aurora VPN Autostart"

Name "${APP_NAME}"
BrandingText "${APP_NAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
; Файлы едут в Program Files, запись — в HKLM: без прав администратора никак.
RequestExecutionLevel admin

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "FileDescription" "${APP_NAME} — установка"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "Aurora VPN"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить ${APP_NAME}"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; Разобранные флаги: заполняются в .onInit и в un.onInit.
Var SilentUpdate
Var RestartAfter

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APP_NAME} собирается только для 64-разрядной Windows."
    Abort
  ${EndIf}

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/UPDATE" $R1
  ${IfNot} ${Errors}
    StrCpy $SilentUpdate "1"
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/R" $R1
  ${IfNot} ${Errors}
    StrCpy $RestartAfter "1"
  ${EndIf}
FunctionEnd

; Снять работающее приложение и ядро.
;
; Мягко попросить нечем: у приложения нет окна, когда оно свёрнуто в трей, а
; файлы всё равно заняты. Встроенное обновление приложения перед запуском
; установщика само опускает туннель и возвращает системный прокси; при ручной
; установке за осиротевшим ядром приберёт kill_orphan на следующем старте.
!macro StopRunning prefix
  nsExec::ExecToStack 'taskkill /F /IM "${APP_EXE}"'
  Pop $0
  nsExec::ExecToStack 'taskkill /F /IM "sing-box.exe"'
  Pop $0
  nsExec::ExecToStack 'taskkill /F /IM "xray.exe"'
  Pop $0
  ; Файлам нужно мгновение, чтобы освободиться после снятия процесса.
  Sleep 800
!macroend

Section "install"
  !insertmacro StopRunning ""

  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "${SOURCE}\${APP_EXE}"
  File "${SOURCE}\sing-box.exe"
  File "${SOURCE}\xray.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Ярлыки — в профиле пользователя, а не «для всех»: туда же приложение кладёт
  ; свой ярлык с AppUserModelID, без которого Windows не принимает от него
  ; уведомления. Один ярлык на одно место, без двойников в меню «Пуск».
  ${If} $SilentUpdate != "1"
    SetShellVarContext current
    CreateShortcut "$SMPROGRAMS\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"

    ; Наследство сборки на WebView2: она ставила ярлыки «для всех», и рядом с
    ; новыми они выглядели бы дубликатами.
    SetShellVarContext all
    Delete "$SMPROGRAMS\${APP_NAME}.lnk"
    Delete "$DESKTOP\${APP_NAME}.lnk"
    SetShellVarContext current
  ${EndIf}

  ; Хлам от сборки на WebView2.
  ;
  ; Сам рантайм WebView2 не трогаем: это общий компонент Microsoft, им живут
  ; Office, Teams и половина настольных приложений — удалять его из-под них
  ; нельзя. А вот профиль браузера, который заводило под себя наше приложение,
  ; после переезда на Slint не нужен никому: восемьдесят мегабайт кэша,
  ; которые больше никогда не откроются.
  SetShellVarContext current
  ${If} ${FileExists} "$LOCALAPPDATA\com.aurora.vpn\EBWebView\*.*"
    RMDir /r "$LOCALAPPDATA\com.aurora.vpn\EBWebView"
    ; Каталог сносится, только если в нём больше ничего нет.
    RMDir "$LOCALAPPDATA\com.aurora.vpn"
  ${EndIf}
  ; Прежний установщик запоминал здесь выбранный язык; наш его не спрашивает.
  DeleteRegKey HKCU "Software\aurora\Aurora VPN"
  DeleteRegKey /ifempty HKCU "Software\aurora"

  ; Запись в списке установленных программ.
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
SectionEnd

; Запуск после установки — только по флагу /R и только в тихом режиме: в обычном
; за это отвечает галочка на последней странице.
Section -Restart
  ${If} $RestartAfter == "1"
  ${AndIf} ${Silent}
    ; Через проводник, чтобы приложение поднялось от пользователя, а не с
    ; правами установщика: свои права оно возьмёт само — задачей планировщика
    ; или запросом UAC, когда они понадобятся.
    Exec '"$WINDIR\explorer.exe" "$INSTDIR\${APP_EXE}"'
  ${EndIf}
SectionEnd

Section "uninstall"
  !insertmacro StopRunning "un."

  ; Автозапуск переживать удаление не должен.
  nsExec::ExecToStack 'schtasks /Delete /TN "${AUTOSTART_TASK}" /F'
  Pop $0
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "AuroraVPN"

  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\sing-box.exe"
  Delete "$INSTDIR\xray.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  SetShellVarContext current
  Delete "$SMPROGRAMS\${APP_NAME}.lnk"
  Delete "$DESKTOP\${APP_NAME}.lnk"
  SetShellVarContext all
  Delete "$SMPROGRAMS\${APP_NAME}.lnk"
  Delete "$DESKTOP\${APP_NAME}.lnk"
  SetShellVarContext current

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKCU "Software\Classes\AppUserModelId\AuroraVPN.Client"

  ; Настройки, серверы и подписки — отдельным вопросом: удалить их молча
  ; значило бы потерять то, что пользователь собирал руками.
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION \
      "Удалить настройки, список серверов и подписки?$\n$\nОтвет «Нет» оставит их на месте — новая установка подхватит всё как было." \
      IDNO keep_data
    RMDir /r "$APPDATA\com.aurora.vpn"
  keep_data:
  ${EndIf}
SectionEnd
