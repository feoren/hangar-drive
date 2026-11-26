; Hooks of the Tauri NSIS installer (tauri.conf.json, bundle.windows.nsis.installerHooks).
;
; Uninstall (security review L1): before the files go, the app forgets the account on this
; device: `--uninstall-cleanup` deletes the device identity and the epoch secrets from the
; Windows Credential Manager and removes the index and settings files (with a per-user install they
; share $INSTDIR, which the uninstaller removes once it is empty). The synced files stay.
; Not on an update ($UpdateMode is 1 when the installer of a newer version runs the uninstaller),
; which must keep the device in its account. A running Hangar Drive is closed first, so it does
; not hold the index open or write its secrets back.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-cleanup'
  ${EndIf}
!macroend
