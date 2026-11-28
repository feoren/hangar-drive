// The header's brand, laid out like Hangar's: the logo over two lines, the name in bold and below it
// the version in small muted text with a "beta" badge while the major version is 0. The version
// comes from the build (vite define), not from a backend call: it is there with the first paint
// and cannot stay empty when a call at start goes unanswered, as it did in an installed build.
// The line keeps its height even without a version, so nothing moves.

import { HANGAR_DRIVE_BUILD, HANGAR_DRIVE_VERSION } from "../buildInfo";
import { useT } from "../i18n";
import { AppLogo } from "../ui/StatusMark";
import { formatVersion, versionParts, withBuild } from "../version";

export function brandVersion(
  version: string | null,
  build: number | null,
): { number: string; beta: boolean } | null {
  return version === null ? null : versionParts(formatVersion(withBuild(version, build)));
}

export function Brand() {
  const t = useT();
  const parts = brandVersion(HANGAR_DRIVE_VERSION, HANGAR_DRIVE_BUILD);
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
