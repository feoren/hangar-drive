// The header's brand, laid out like Hangar's: the logo over two lines, the name in bold and below it
// the version in small muted text with a "beta" badge while the major version is 0. The version
// line keeps its height before the version arrives (or if it never does), so nothing moves.

import { HANGAR_DRIVE_BUILD } from "../buildInfo";
import { useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import { AppLogo } from "../ui/StatusMark";
import { useLoad } from "../ui/useAsync";
import { formatVersion, versionParts, withBuild } from "../version";

export function Brand() {
  const t = useT();
  const backend = useBackend();
  const [about] = useLoad(() => backend.getAbout(), [backend]);
  const parts =
    about.status === "ready"
      ? versionParts(
          formatVersion(withBuild(about.data.version, about.data.build ?? HANGAR_DRIVE_BUILD)),
        )
      : null;
  return (
    <span className="brand">
      <AppLogo size={26} className="brand-mark" />
      <span className="brand-name">{t("app.name")}</span>
      <span className="brand-version" aria-hidden={parts === null ? true : undefined}>
        {parts && (
          <>
            {parts.number}
            {parts.beta && <span className="beta-badge">{t("version.beta")}</span>}
          </>
        )}
      </span>
    </span>
  );
}
