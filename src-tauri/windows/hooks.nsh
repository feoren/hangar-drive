; Hooks of the Tauri NSIS installer (tauri.conf.json, bundle.windows.nsis.installerHooks).
;
; Uninstall (security review L1, narrowed after the installer upgrade finding): before the files
; go, the app forgets the account on this device only when the person ticked the uninstaller's
; "delete app data" box (worded in windows/German.nsh and windows/English.nsh to name the device
; keys). `--uninstall-cleanup` then deletes the device identity and the epoch secrets from the
; Windows Credential Manager and removes the index and settings files (with a per-user install
; they share $INSTDIR, which the uninstaller removes once it is empty). The synced files stay.
;
; Without the tick everything stays, because an interactive upgrade or downgrade runs this same
; uninstaller: the newer installer's preselected "uninstall before installing" starts it without
; /UPDATE ($UpdateMode is 1 only when the updater ran the installer with /UPDATE), so a check of
; $UpdateMode alone would wipe the device's keys on every manual upgrade. The box's state is read
; when the confirmation page is left (un.ConfirmLeave of the Tauri template), before the
; uninstall section runs; a silent (/S) or passive (/P) uninstall never shows that page, so the
; state stays empty and the keys stay. A running Hangar Drive is closed first, so it does not
; hold the index open or write its secrets back.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
  ${AndIf} $DeleteAppDataCheckboxState = 1
    !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-cleanup'
  ${EndIf}
!macroend
