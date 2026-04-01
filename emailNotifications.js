import { Resend } from "resend";

const escapeHtml = (value = "") =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const normalizeEventLabel = (eventType = "wedding") => {
  const key = String(eventType || "").toLowerCase();
  const map = {
    wedding: "Nunta",
    baptism: "Botez",
    anniversary: "Aniversare",
    kids: "Petrecere copii",
    office: "Eveniment corporate",
    birthday: "Zi de nastere",
  };
  return map[key] || key || "Eveniment";
};

const formatDate = (value) => {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString("ro-RO", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
};

const formatDateTime = (value) => {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString("ro-RO", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const sanitizeSubject = (value = "") =>
  String(value)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 140);

const EMAIL_THEMES = {
  slate: {
    pageBg: "#f4f4f5",
    headerBg: "#fafafa",
    accent: "#18181b",
    accentSoft: "#f4f4f5",
    accentBorder: "#d4d4d8",
    ctaBg: "#18181b",
    ctaText: "#ffffff",
  },
  indigo: {
    pageBg: "#f5f7ff",
    headerBg: "#f1f4ff",
    accent: "#4f46e5",
    accentSoft: "#eef2ff",
    accentBorder: "#c7d2fe",
    ctaBg: "#4f46e5",
    ctaText: "#ffffff",
  },
  emerald: {
    pageBg: "#f5fbf7",
    headerBg: "#effaf3",
    accent: "#059669",
    accentSoft: "#ecfdf5",
    accentBorder: "#a7f3d0",
    ctaBg: "#059669",
    ctaText: "#ffffff",
  },
  sky: {
    pageBg: "#f3f9ff",
    headerBg: "#edf6ff",
    accent: "#0284c7",
    accentSoft: "#e0f2fe",
    accentBorder: "#bae6fd",
    ctaBg: "#0284c7",
    ctaText: "#ffffff",
  },
  amber: {
    pageBg: "#fffbf2",
    headerBg: "#fff7e6",
    accent: "#b45309",
    accentSoft: "#fef3c7",
    accentBorder: "#fcd34d",
    ctaBg: "#b45309",
    ctaText: "#ffffff",
  },
  rose: {
    pageBg: "#fff5f8",
    headerBg: "#fff0f4",
    accent: "#be185d",
    accentSoft: "#ffe4ee",
    accentBorder: "#fecdd3",
    ctaBg: "#be185d",
    ctaText: "#ffffff",
  },
  violet: {
    pageBg: "#f7f5ff",
    headerBg: "#f2edff",
    accent: "#7c3aed",
    accentSoft: "#ede9fe",
    accentBorder: "#ddd6fe",
    ctaBg: "#7c3aed",
    ctaText: "#ffffff",
  },
  red: {
    pageBg: "#fff5f5",
    headerBg: "#fff1f2",
    accent: "#dc2626",
    accentSoft: "#fee2e2",
    accentBorder: "#fecaca",
    ctaBg: "#dc2626",
    ctaText: "#ffffff",
  },
};

const renderEmailLayout = ({
  appName,
  headerLabel = "Notificare",
  title = "",
  intro = "",
  contentHtml = "",
  ctaLabel = "",
  ctaUrl = "",
  footerNote = "",
  theme = "slate",
}) => {
  const t = EMAIL_THEMES[theme] || EMAIL_THEMES.slate;
  const safeApp = escapeHtml(appName || "WeddingPro");
  const safeHeaderLabel = escapeHtml(headerLabel);
  const safeTitle = escapeHtml(title);
  const safeIntro = escapeHtml(intro);
  const safeFooter = escapeHtml(footerNote || `Email automat trimis de ${safeApp}.`);
  const hasCta = Boolean(ctaLabel && ctaUrl);

  return `
    <div style="margin:0;padding:0;background:${t.pageBg};font-family:Inter,Segoe UI,Arial,sans-serif;color:#18181b">
      <div style="max-width:620px;margin:0 auto;padding:28px 14px">
        <div style="background:#ffffff;border:1px solid #e4e4e7;border-radius:18px;overflow:hidden;box-shadow:0 8px 28px rgba(24,24,27,.06)">
          <div style="height:4px;background:${t.accent}"></div>
          <div style="padding:20px 24px;border-bottom:1px solid #e4e4e7;background:linear-gradient(180deg,#ffffff 0%,${t.headerBg} 100%)">
            <div style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:5px 10px;border-radius:999px;border:1px solid ${t.accentBorder};color:${t.accent};background:${t.accentSoft}">${safeHeaderLabel}</div>
            <h1 style="margin:14px 0 8px;font-size:24px;line-height:1.25;font-weight:700;color:#09090b">${safeTitle}</h1>
            ${safeIntro ? `<p style="margin:0;font-size:14px;line-height:1.6;color:#3f3f46">${safeIntro}</p>` : ""}
          </div>

          <div style="padding:24px">
            ${contentHtml}
            ${
              hasCta
                ? `<div style="margin-top:18px">
                    <a href="${escapeHtml(ctaUrl)}" style="display:inline-block;padding:10px 16px;background:${t.ctaBg};color:${t.ctaText};text-decoration:none;border-radius:10px;font-size:13px;font-weight:600;box-shadow:0 6px 16px rgba(0,0,0,.12)">
                      ${escapeHtml(ctaLabel)}
                    </a>
                  </div>`
                : ""
            }
          </div>

          <div style="padding:14px 24px;border-top:1px solid #e4e4e7;background:#fafafa;color:#71717a;font-size:12px;line-height:1.55">
            ${safeFooter}
          </div>
        </div>

        <p style="margin:12px 2px 0;color:#a1a1aa;font-size:11px;text-align:center">
          © ${new Date().getFullYear()} ${safeApp}
        </p>
      </div>
    </div>
  `;
};

const renderInfoCard = (rows = [], theme = "slate") => {
  const t = EMAIL_THEMES[theme] || EMAIL_THEMES.slate;
  const htmlRows = rows
    .filter((r) => r && r.label && String(r.value || "").trim())
    .map(
      (r) => `
        <tr>
          <td style="padding:8px 0;border-bottom:1px solid #f4f4f5;font-size:13px;color:#71717a;vertical-align:top">
            ${escapeHtml(r.label)}:
          </td>
          <td align="right" style="padding:8px 0;border-bottom:1px solid #f4f4f5;font-size:13px;color:#18181b;font-weight:600;text-align:right;vertical-align:top;padding-left:14px">
            ${escapeHtml(r.value)}
          </td>
        </tr>
      `,
    )
    .join("");

  return `
    <div style="border:1px solid ${t.accentBorder};border-radius:12px;background:${t.accentSoft};padding:8px 12px">
      ${
        htmlRows
          ? `<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse">${htmlRows}</table>`
          : `<div style="font-size:13px;color:#71717a;padding:4px 0">Fara detalii suplimentare.</div>`
      }
    </div>
  `;
};

export function createEmailNotifications({
  apiKey = "",
  from = "WeddingPro <onboarding@resend.dev>",
  appName = "WeddingPro",
  clientUrl = "",
  logger = console,
}) {
  const resend = apiKey ? new Resend(apiKey) : null;

  const send = async ({ to, subject, html, attachments = [] }) => {
    if (!resend) {
      logger.warn("[EMAIL] RESEND_API_KEY missing. Email not sent:", subject, "=>", to);
      return false;
    }
    try {
      const payload = {
        from,
        to: [to],
        subject,
        html,
      };
      if (Array.isArray(attachments) && attachments.length) {
        payload.attachments = attachments;
      }
      await resend.emails.send(payload);
      return true;
    } catch (error) {
      logger.error("[EMAIL] Failed send:", subject, "=>", to, error);
      return false;
    }
  };

  const sendVerificationOtp = async ({ email, otp, ttlMinutes = 10 }) => {
    const safeOtp = escapeHtml(otp || "");
    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Foloseste codul de mai jos pentru verificarea contului.
      </p>
      <div style="margin:0 0 12px;border:1px solid #d4d4d8;border-radius:12px;background:#ffffff;padding:16px;text-align:center">
        <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:34px;font-weight:700;letter-spacing:0.24em;color:#09090b">${safeOtp}</div>
      </div>
      <p style="margin:0 0 8px;font-size:13px;color:#52525b">Codul expira in ${Number(ttlMinutes)} minute.</p>
      <p style="margin:0;font-size:12px;color:#71717a">Daca nu ai initiat aceasta actiune, ignora acest email.</p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Security",
      title: "Cod OTP pentru verificare email",
      intro: `Contul tau ${appName} asteapta confirmarea adresei de email.`,
      contentHtml,
      footerNote: "Acest cod este strict personal si nu trebuie transmis altor persoane.",
      theme: "indigo",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Cod verificare email ${appName}`),
      html,
    });
  };

  const sendPasswordResetOtp = async ({ email, name = "", otp, ttlMinutes = 10 }) => {
    const safeName = escapeHtml(name || "prietene");
    const safeOtp = escapeHtml(otp || "");
    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Ai cerut resetarea parolei.
      </p>
      <div style="margin:0 0 12px;border:1px solid #d4d4d8;border-radius:12px;background:#ffffff;padding:16px;text-align:center">
        <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:34px;font-weight:700;letter-spacing:0.24em;color:#09090b">${safeOtp}</div>
      </div>
      <p style="margin:0 0 8px;font-size:13px;color:#52525b">Codul expira in ${Number(ttlMinutes)} minute.</p>
      <p style="margin:0;font-size:12px;color:#71717a">Daca nu ai solicitat resetarea parolei, ignora acest email.</p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Password Reset",
      title: "Cod OTP pentru resetare parola",
      intro: `Cerere de resetare parola pentru contul ${appName}.`,
      contentHtml,
      theme: "indigo",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Cod resetare parola ${appName}`),
      html,
    });
  };

  const sendPasswordChangedEmail = async ({
    email,
    name = "",
    changedAt = new Date(),
    ip = "",
    userAgent = "",
  }) => {
    const safeName = escapeHtml(name || "prietene");
    const safeDateTime = formatDateTime(changedAt);
    const safeIp = String(ip || "necunoscut");
    const safeUa = String(userAgent || "necunoscut").slice(0, 240);

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Parola contului tau a fost schimbata.
      </p>
      ${renderInfoCard([
        { label: "Data si ora", value: safeDateTime },
        { label: "IP", value: safeIp },
        { label: "Browser", value: safeUa },
      ], "emerald")}
      <p style="margin:12px 0 0;font-size:13px;color:#52525b">
        Daca nu ai facut tu aceasta schimbare, reseteaza parola imediat si contacteaza suportul.
      </p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Security",
      title: "Parola contului a fost schimbata",
      intro: "Notificare de securitate.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide aplicatia" : "",
      ctaUrl: clientUrl || "",
      theme: "emerald",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Parola contului a fost schimbata - ${appName}`),
      html,
    });
  };

  const sendVerificationSuccessEmail = async ({ email, name = "" }) => {
    const safeName = escapeHtml(name || "prietene");
    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Emailul tau a fost verificat cu succes.
      </p>
      <div style="display:inline-block;padding:6px 11px;border-radius:999px;border:1px solid #d4d4d8;background:#fafafa;font-size:12px;font-weight:700;letter-spacing:.03em;color:#18181b">
        Verificare completata
      </div>
      <p style="margin:12px 0 0;font-size:13px;color:#52525b">
        Poti continua configurarea evenimentului direct din dashboard.
      </p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Account",
      title: "Email verificat cu succes",
      intro: "Contul tau este activ.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide dashboard" : "",
      ctaUrl: clientUrl || "",
      theme: "emerald",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Email verificat cu succes - ${appName}`),
      html,
    });
  };

  const sendWelcomeEmail = async ({
    email,
    name = "",
    eventType = "wedding",
    eventName = "",
    eventDate,
  }) => {
    const safeName = escapeHtml(name || "prietene");
    const safeEventLabel = normalizeEventLabel(eventType);
    const safeEventName = String(eventName || "").trim();
    const safeDate = formatDate(eventDate);

    const detailsHtml = renderInfoCard([
      { label: "Tip eveniment ", value: safeEventLabel },
      { label: "Nume eveniment ", value: safeEventName },
      { label: "Data", value: safeDate },
    ], "violet");

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Configurarea evenimentului tau este gata.
      </p>
      ${detailsHtml}
      <p style="margin:12px 0 0;font-size:13px;color:#52525b">
        Totul este pregatit. Poti continua personalizarea invitatiei.
      </p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Welcome",
      title: "Bine ai venit",
      intro: "Evenimentul tau a fost configurat cu succes.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide dashboard" : "",
      ctaUrl: clientUrl || "",
      theme: "violet",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Evenimentul tau este gata in ${appName}`),
      html,
    });
  };

  const sendLoginAlertEmail = async ({
    email,
    ip = "",
    userAgent = "",
    loginAt = new Date(),
  }) => {
    const safeIp = String(ip || "necunoscut");
    const safeUa = String(userAgent || "necunoscut").slice(0, 240);
    const safeDateTime = formatDateTime(loginAt);

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        A fost detectata o conectare noua in contul tau.
      </p>
      ${renderInfoCard([
        { label: "Data si ora", value: safeDateTime },
        { label: "IP", value: safeIp },
        { label: "Browser", value: safeUa },
      ], "amber")}
      <p style="margin:12px 0 0;font-size:13px;color:#52525b">
        Daca nu recunosti aceasta activitate, schimba parola imediat.
      </p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Security",
      title: "Alerta conectare cont",
      intro: `Monitorizare automata ${appName}.`,
      contentHtml,
      ctaLabel: clientUrl ? "Verifica contul" : "",
      ctaUrl: clientUrl || "",
      theme: "amber",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Alerta conectare ${appName}`),
      html,
    });
  };

  const sendEventReminderEmail = async ({
    email,
    name = "",
    eventType = "wedding",
    eventName = "",
    eventDate,
    daysLeft,
  }) => {
    const safeName = escapeHtml(name || "prietene");
    const safeEventLabel = normalizeEventLabel(eventType);
    const safeEventName = String(eventName || "").trim();
    const safeDate = formatDate(eventDate);
    const safeDays = Number.isFinite(Number(daysLeft)) ? Number(daysLeft) : null;
    const countdownText =
      safeDays === null
        ? "Evenimentul tau se apropie."
        : `Au mai ramas ${safeDays} zile pana la eveniment.`;

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>!
      </p>
      <div style="padding:10px 12px;border:1px solid #d4d4d8;border-radius:12px;background:#ffffff;font-size:13px;font-weight:700;color:#18181b;margin:0 0 12px">
        ${escapeHtml(countdownText)}
      </div>
      ${renderInfoCard([
        { label: "Tip eveniment", value: safeEventLabel },
        { label: "Nume eveniment", value: safeEventName },
        { label: "Data", value: safeDate },
      ], "sky")}
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Reminder",
      title: "Reminder eveniment",
      intro: "Revino in dashboard pentru ultimele ajustari.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide dashboard" : "",
      ctaUrl: clientUrl || "",
      theme: "sky",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Reminder eveniment - ${appName}`),
      html,
    });
  };

  const sendAdminNotificationEmail = async ({
    email,
    name = "",
    title = "",
    message = "",
    priority = "normal",
  }) => {
    const safeName = escapeHtml(name || "utilizator");
    const normalizedPriority = String(priority || "").toLowerCase() === "high" ? "high" : "normal";
    const priorityLabel = normalizedPriority === "high" ? "HIGH PRIORITY" : "NORMAL PRIORITY";
    const plainTitle = sanitizeSubject(title || "Notificare");
    const plainMessage = String(message || "").trim();
    const priorityTheme = normalizedPriority === "high" ? "red" : "violet";
    const priorityPillBg = normalizedPriority === "high" ? "#fee2e2" : "#ede9fe";
    const priorityPillBorder = normalizedPriority === "high" ? "#fecaca" : "#ddd6fe";
    const priorityPillColor = normalizedPriority === "high" ? "#b91c1c" : "#6d28d9";

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Ai primit un mesaj nou de la echipa.
      </p>
      <div style="display:inline-block;margin:0 0 12px;padding:6px 11px;border-radius:999px;border:1px solid ${priorityPillBorder};background:${priorityPillBg};font-size:11px;font-weight:700;letter-spacing:.06em;color:${priorityPillColor}">
        ${escapeHtml(priorityLabel)}
      </div>
      ${renderInfoCard([
        { label: "Titlu", value: plainTitle },
        { label: "Mesaj", value: plainMessage },
      ], priorityTheme)}
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Admin Message",
      title: plainTitle || "Notificare noua",
      intro: "Aceasta notificare a fost trimisa direct din platforma.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide aplicatia" : "",
      ctaUrl: clientUrl || "",
      theme: priorityTheme,
    });

    return send({
      to: email,
      subject: sanitizeSubject(`${normalizedPriority === "high" ? "[HIGH] " : ""}${plainTitle} - ${appName}`),
      html,
    });
  };

  const sendGuestRsvpEmail = async ({
    email,
    ownerName = "",
    guestName = "",
    status = "pending",
    rsvpData = {},
    eventType = "wedding",
    eventName = "",
    eventDate,
  }) => {
    const safeOwner = escapeHtml(ownerName || "organizator");
    const safeGuest = String(guestName || "").trim() || "Invitat";
    const normalizedStatus = String(status || "").toLowerCase();
    const statusLabel =
      normalizedStatus === "confirmed"
        ? "CONFIRMAT"
        : normalizedStatus === "declined"
          ? "REFUZAT"
          : "INREGISTRAT";
    const rsvpTheme =
      normalizedStatus === "confirmed"
        ? "emerald"
        : normalizedStatus === "declined"
          ? "rose"
          : "sky";
    const statusPillBg =
      normalizedStatus === "confirmed"
        ? "#dcfce7"
        : normalizedStatus === "declined"
          ? "#ffe4ee"
          : "#e0f2fe";
    const statusPillBorder =
      normalizedStatus === "confirmed"
        ? "#86efac"
        : normalizedStatus === "declined"
          ? "#fecdd3"
          : "#bae6fd";
    const statusPillColor =
      normalizedStatus === "confirmed"
        ? "#166534"
        : normalizedStatus === "declined"
          ? "#be185d"
          : "#0369a1";

    const adults = Number(rsvpData?.adultsCount || 0);
    const children = Number(rsvpData?.childrenCount || 0);
    const total = Number(rsvpData?.confirmedCount || 0);
    const guestMessage = String(rsvpData?.message || "").trim();

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeOwner}</b>! Invitatul <b style="color:#09090b">${escapeHtml(safeGuest)}</b> a trimis raspunsul RSVP.
      </p>
      <div style="display:inline-block;margin:0 0 12px;padding:6px 11px;border-radius:999px;border:1px solid ${statusPillBorder};background:${statusPillBg};font-size:11px;font-weight:700;letter-spacing:.06em;color:${statusPillColor}">
        Status: ${escapeHtml(statusLabel)}
      </div>
      ${renderInfoCard([
        { label: "Tip eveniment ", value: normalizeEventLabel(eventType) },
        { label: "Nume eveniment ", value: eventName },
        { label: "Data eveniment ", value: formatDate(eventDate) },
        { label: "Total persoane ", value: String(Number.isFinite(total) ? total : 0) },
        { label: "Adulti ", value: String(Number.isFinite(adults) ? adults : 0) },
        { label: "Copii ", value: String(Number.isFinite(children) ? children : 0) },
      ], rsvpTheme)}
      ${
        guestMessage
          ? `<div style="margin-top:12px;padding:10px 12px;border:1px solid #e4e4e7;border-radius:12px;background:#ffffff">
               <div style="font-size:12px;color:#71717a;margin-bottom:6px">Mesaj invitat</div>
               <div style="font-size:13px;color:#18181b;line-height:1.55"> ${escapeHtml(guestMessage)} </div>
             </div>`
          : ""
      }
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "RSVP",
      title: "Actualizare RSVP invitat",
      intro: "Notificare automata dupa raspunsul invitatului.",
      contentHtml,
      ctaLabel: clientUrl ? "Deschide dashboard" : "",
      ctaUrl: clientUrl || "",
      theme: rsvpTheme,
    });

    return send({
      to: email,
      subject: sanitizeSubject(`RSVP ${statusLabel} - ${safeGuest}`),
      html,
    });
  };

  const sendBillingInvoiceEmail = async ({
    email,
    name = "",
    invoiceNumber = "",
    amount = 0,
    currency = "RON",
    issueDate = new Date(),
    eventName = "",
    invoiceUrl = "",
    attachments = [],
  }) => {
    const safeName = escapeHtml(name || "client");
    const safeInvoice = escapeHtml(invoiceNumber || "-");
    const safeAmount = `${Number(amount || 0).toFixed(2)} ${escapeHtml(currency || "RON")}`;
    const safeDate = formatDate(issueDate);

    const contentHtml = `
      <p style="margin:0 0 12px;font-size:14px;color:#3f3f46">
        Salut, <b style="color:#09090b">${safeName}</b>! Factura dumneavoastra este emisa si atasata acestui email.
      </p>
      ${renderInfoCard([
        { label: "Numar factura", value: safeInvoice },
        { label: "Data emiterii", value: safeDate },
        { label: "Valoare", value: safeAmount },
        { label: "Eveniment", value: String(eventName || "").trim() || "-" },
      ], "indigo")}
      <p style="margin:12px 0 0;font-size:13px;color:#52525b">
        Daca aveti nevoie de asistenta, raspundeti direct la acest email.
      </p>
    `;

    const html = renderEmailLayout({
      appName,
      headerLabel: "Facturare",
      title: "Factura dumneavoastra",
      intro: "Document fiscal emis dupa confirmarea platii.",
      contentHtml,
      ctaLabel: invoiceUrl ? "Deschide factura online" : "",
      ctaUrl: invoiceUrl || "",
      theme: "indigo",
    });

    return send({
      to: email,
      subject: sanitizeSubject(`Factura ${invoiceNumber || ""} - ${appName}`),
      html,
      attachments,
    });
  };

  return {
    isEnabled: Boolean(resend),
    sendVerificationOtp,
    sendPasswordResetOtp,
    sendPasswordChangedEmail,
    sendVerificationSuccessEmail,
    sendWelcomeEmail,
    sendLoginAlertEmail,
    sendEventReminderEmail,
    sendAdminNotificationEmail,
    sendGuestRsvpEmail,
    sendBillingInvoiceEmail,
  };
}
