// The network traffic in the header (UX 6.3), after the system bar of the sister app: upload and
// download each as a small tile whose background is the sparkline of the last minute, with the
// arrow and the current rate on top of it; the totals since the start are in the tooltip. A quiet
// minute hides the line, so an idle connection shows nothing at all.

import { formatSize } from "../format";
import { useLanguage, useT } from "../i18n";
import { useBackend } from "../ui/backendContext";
import {
  currentRate,
  formatRate,
  isQuiet,
  scaleTop,
  SPARK_HEIGHT,
  SPARK_WIDTH,
  sparkPaths,
  type History,
} from "./traffic";
import { useTraffic } from "./trafficStore";

export function TrafficBar() {
  const t = useT();
  const language = useLanguage();
  const traffic = useTraffic(useBackend());
  if (isQuiet(traffic)) return null;
  const top = scaleTop(traffic);
  const upRate = formatRate(language, currentRate(traffic.up));
  const downRate = formatRate(language, currentRate(traffic.down));
  const up = t("traffic.up", { rate: upRate });
  const down = t("traffic.down", { rate: downRate });
  const session = t("traffic.session", {
    sent: formatSize(language, traffic.sent),
    received: formatSize(language, traffic.received),
  });
  return (
    <div
      className="traffic"
      role="group"
      aria-label={t("traffic.label")}
      title={[up, down, session].join("\n")}
    >
      <TrafficGauge
        direction="up"
        arrow="↑"
        label={up}
        rate={upRate}
        history={traffic.up}
        top={top}
        tick={traffic.tick}
      />
      <TrafficGauge
        direction="down"
        arrow="↓"
        label={down}
        rate={downRate}
        history={traffic.down}
        top={top}
        tick={traffic.tick}
      />
      <span className="sr-only">{session}</span>
    </div>
  );
}

function TrafficGauge({
  direction,
  arrow,
  label,
  rate,
  history,
  top,
  tick,
}: {
  readonly direction: "up" | "down";
  readonly arrow: string;
  /** "Hochladen: 5,2 MB/s", for screen readers. */
  readonly label: string;
  readonly rate: string;
  readonly history: History;
  readonly top: number;
  readonly tick: number;
}) {
  const paths = sparkPaths(history, top);
  return (
    <span className={`traffic-gauge traffic-${direction}`}>
      <svg
        className="traffic-spark"
        viewBox={`0 0 ${String(SPARK_WIDTH)} ${String(SPARK_HEIGHT)}`}
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        {paths !== null && (
          // A new key per reading restarts the scroll animation.
          <g key={tick} className="traffic-scroll">
            <path className="traffic-area" d={paths.area} />
            <path className="traffic-line" d={paths.line} />
          </g>
        )}
      </svg>
      <span className="traffic-arrow" aria-hidden="true">
        {arrow}
      </span>
      <span className="traffic-rate" aria-hidden="true">
        {rate}
      </span>
      <span className="sr-only">{label}</span>
    </span>
  );
}
