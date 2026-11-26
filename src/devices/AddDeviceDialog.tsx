// Adding a device, seen from this device (UX 5): a code to scan or a link to copy, valid until a
// fixed time. When the new device answers, the window shows who wants to join, with "Decline"
// and "Add ...". The question itself, with the numbers to compare, is the native one the shell
// asks after "Add ..." (security review L2); the window does not ask it a second time.
// One dialog throughout, so focus moves to the new question instead of jumping out and back.

import { useEffect, useId, useState } from "react";

import type { PairingOffer, PairRequest } from "../backend/types";
import { groupHex } from "../domain/links";
import { formatTime } from "../format";
import { useLanguage, useT } from "../i18n";
import { useBackendEvent } from "../ui/appContext";
import { useBackend } from "../ui/backendContext";
import { Dialog } from "../ui/Dialog";
import { ArmedButton, Feedback, Loading, NumberRows, QrCode } from "../ui/parts";
import { errorText, useAction } from "../ui/useAsync";

export function AddDeviceDialog({
  onAdded,
  onClose,
}: {
  readonly onAdded: (name: string) => void;
  readonly onClose: () => void;
}) {
  const backend = useBackend();
  const titleId = useId();
  const action = useAction();
  const [offer, setOffer] = useState<PairingOffer | null>(null);
  const [offerError, setOfferError] = useState<unknown>(null);
  const [round, setRound] = useState(0);
  const [expired, setExpired] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [request, setRequest] = useState<PairRequest | null>(null);
  const [declined, setDeclined] = useState(false);

  useEffect(() => {
    let current = true;
    backend.createPairingOffer().then(
      (created) => {
        if (!current) return;
        setOffer(created);
        setExpired(false);
      },
      (error: unknown) => {
        if (current) setOfferError(error);
      },
    );
    return () => {
      current = false;
    };
  }, [backend, round]);

  // A fixed time, not a countdown: the code turns into "expired" when the time has come.
  useEffect(() => {
    if (!offer) return;
    const timer = setTimeout(
      () => {
        setExpired(true);
      },
      Math.max(0, offer.expiresAt - Date.now()),
    );
    return () => {
      clearTimeout(timer);
    };
  }, [offer]);

  useBackendEvent((event) => {
    if (event.type === "pairRequest" && event.request.offerId === offer?.id)
      setRequest(event.request);
    if (event.type === "pairRequestGone" && event.offerId === offer?.id) {
      setRequest(null);
      setExpired(true);
    }
  });

  const answer = (accept: boolean) => {
    if (!request) return;
    void action.run(async () => {
      const answer = await backend.answerPairRequest(request.offerId, accept);
      if (answer === "added") {
        onAdded(request.deviceName);
        onClose();
      } else {
        setRequest(null);
        setDeclined(true);
      }
    });
  };

  const stage = declined ? "declined" : request ? "request" : "offer";
  return (
    <Dialog
      labelledBy={titleId}
      size={stage === "offer" ? "medium" : "small"}
      focusKey={stage === "offer" ? `offer-${offer?.id ?? "loading"}-${String(expired)}` : stage}
      closeOnOutside={stage !== "request"}
      role={stage === "request" ? "alertdialog" : "dialog"}
      onClose={() => {
        if (stage === "request") answer(false);
        else onClose();
      }}
    >
      {stage === "declined" && <DeclinedView titleId={titleId} onClose={onClose} />}
      {stage === "request" && request && (
        <RequestView
          titleId={titleId}
          request={request}
          pending={action.pending}
          error={action.error}
          onAnswer={answer}
        />
      )}
      {stage === "offer" && (
        <OfferView
          titleId={titleId}
          offer={offer}
          offerError={offerError}
          expired={expired}
          copied={copied}
          showCode={showCode}
          pending={action.pending}
          error={action.error}
          onRenew={() => {
            setOffer(null);
            setShowCode(false);
            setCopied(false);
            setRound((value) => value + 1);
          }}
          onCopy={(offerId) => {
            void action.run(async () => {
              await backend.copyPairingLink(offerId);
              setCopied(true);
            });
          }}
          onShowCode={() => {
            setShowCode(true);
          }}
          onClose={onClose}
        />
      )}
    </Dialog>
  );
}

function DeclinedView({
  titleId,
  onClose,
}: {
  readonly titleId: string;
  readonly onClose: () => void;
}) {
  const t = useT();
  return (
    <>
      <h2 id={titleId} className="dialog-title">
        {t("pair.add.title")}
      </h2>
      <p className="dialog-body">{t("pair.mismatch")}</p>
      <div className="dialog-actions">
        <button type="button" className="button primary" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      </div>
    </>
  );
}

function RequestView({
  titleId,
  request,
  pending,
  error,
  onAnswer,
}: {
  readonly titleId: string;
  readonly request: PairRequest;
  readonly pending: boolean;
  readonly error: unknown;
  readonly onAnswer: (accept: boolean) => void;
}) {
  const t = useT();
  const typed = request.path === "typed";
  return (
    <>
      <h2 id={titleId} className="dialog-title">
        {t("pair.confirm.title", { device: request.deviceName })}
      </h2>
      <p className="dialog-body">{t("pair.request.body")}</p>
      {typed ? (
        <NumberRows rows={request.safety} label={t("safety.label")} />
      ) : (
        <details className="disclosure">
          <summary>{t("pair.numbers.compare")}</summary>
          <NumberRows rows={request.safety} label={t("safety.label")} />
        </details>
      )}
      {error !== null && <Feedback tone="error">{errorText(error, t)}</Feedback>}
      <div className="dialog-actions">
        <button
          type="button"
          className="button secondary"
          data-autofocus
          disabled={pending}
          onClick={() => {
            onAnswer(false);
          }}
        >
          {t("pair.confirm.decline")}
        </button>
        <ArmedButton
          armKey={request.offerId + request.safety.groups.join("")}
          onClick={() => {
            onAnswer(true);
          }}
        >
          {t("pair.confirm.add")}
        </ArmedButton>
      </div>
    </>
  );
}

function OfferView({
  titleId,
  offer,
  offerError,
  expired,
  copied,
  showCode,
  pending,
  error,
  onRenew,
  onCopy,
  onShowCode,
  onClose,
}: {
  readonly titleId: string;
  readonly offer: PairingOffer | null;
  readonly offerError: unknown;
  readonly expired: boolean;
  readonly copied: boolean;
  readonly showCode: boolean;
  readonly pending: boolean;
  readonly error: unknown;
  readonly onRenew: () => void;
  readonly onCopy: (offerId: string) => void;
  readonly onShowCode: () => void;
  readonly onClose: () => void;
}) {
  const t = useT();
  const language = useLanguage();
  const app = t("app.name");
  return (
    <>
      <h2 id={titleId} className="dialog-title">
        {t("pair.add.title")}
      </h2>
      <ol className="steps compact">
        <li className="step">{t("pair.add.step1", { app })}</li>
        <li className="step">{t("pair.add.step2", { app })}</li>
        <li className="step">{t("pair.add.step3")}</li>
      </ol>
      {offerError !== null ? (
        <Feedback tone="error">{errorText(offerError, t)}</Feedback>
      ) : !offer ? (
        <Loading />
      ) : expired ? (
        <div className="offer offer-expired">
          <p>{t("pair.add.expired")}</p>
          <button type="button" className="button primary" data-autofocus onClick={onRenew}>
            {t("pair.add.renew")}
          </button>
        </div>
      ) : (
        <div className="offer">
          <QrCode svg={offer.qrSvg} label={t("pair.add.qrLabel")} />
          <div className="offer-side">
            <button
              type="button"
              className="button primary"
              data-autofocus
              disabled={pending}
              onClick={() => {
                onCopy(offer.id);
              }}
            >
              {t("pair.add.copyLink")}
            </button>
            {copied && <Feedback>{t("pair.add.copied")}</Feedback>}
            <p className="muted">
              {t("pair.add.validUntil", { time: formatTime(language, offer.expiresAt) })}
            </p>
            <p className="muted">
              {t("pair.add.target", { host: offer.host, account: groupHex(offer.account) })}
            </p>
            {showCode ? (
              <div className="typed-code">
                <p className="muted">{t("pair.add.codeServer", { host: offer.host })}</p>
                <p className="code-line" aria-label={t("pair.new.codeLabel")}>
                  {offer.code.join(" ")}
                </p>
              </div>
            ) : (
              <button type="button" className="link-button" onClick={onShowCode}>
                {t("pair.add.showCode")}
              </button>
            )}
          </div>
        </div>
      )}
      {error !== null && <Feedback tone="error">{errorText(error, t)}</Feedback>}
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("common.cancel")}
        </button>
      </div>
    </>
  );
}
