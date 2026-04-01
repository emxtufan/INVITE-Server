import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const CREATE_INVOICE_URL = 'https://ws.smartbill.ro/SBORO/api/invoice';
const CREATE_PAYMENT_URL = 'https://ws.smartbill.ro/SBORO/api/payment';
const SEND_DOCUMENT_URL = 'https://ws.smartbill.ro/SBORO/api/document/send';
const GET_INVOICE_PDF_URL = 'https://ws.smartbill.ro/SBORO/api/invoice/pdf';

function getSmartbillEnv() {
  return {
    username: process.env.SMARTBILL_USERNAME || '',
    token: process.env.SMARTBILL_TOKEN || '',
    cif: process.env.SMARTBILL_CIF || '',
    series: process.env.SMARTBILL_SERIES || '',
    sendEmail: process.env.SMARTBILL_SEND_EMAIL !== 'false',
    debug: process.env.SMARTBILL_DEBUG === 'true',
    individualVatCode: process.env.SMARTBILL_INDIVIDUAL_VAT_CODE || '0000000000000',
  };
}

const sanitize = (value, max = 255) => String(value ?? '').trim().slice(0, max);
const digitsOnly = (value) => sanitize(value, 64).replace(/\D/g, '');
const toBase64 = (text) => Buffer.from(String(text ?? ''), 'utf8').toString('base64');
const getToday = () => new Date().toISOString().slice(0, 10);
const addDays = (days = 14) => {
  const d = new Date();
  d.setDate(d.getDate() + Number(days || 0));
  return d.toISOString().slice(0, 10);
};

function getAuthHeader() {
  const { username, token } = getSmartbillEnv();
  const raw = `${username}:${token}`;
  return `Basic ${Buffer.from(raw).toString('base64')}`;
}

function mask(value, visibleStart = 3, visibleEnd = 2) {
  const s = String(value ?? '');
  if (!s) return '';
  if (s.length <= visibleStart + visibleEnd) return '*'.repeat(Math.max(s.length, 4));
  return `${s.slice(0, visibleStart)}***${s.slice(-visibleEnd)}`;
}

function debugLog(label, data) {
  if (!getSmartbillEnv().debug) return;
  if (typeof data === 'undefined') {
    console.log(`[SMARTBILL][DEBUG] ${label}`);
    return;
  }
  console.log(`[SMARTBILL][DEBUG] ${label}`, data);
}

function smartbillConfigured() {
  const { username, token, cif, series, debug } = getSmartbillEnv();
  const configured = Boolean(username && token && cif && series);
  if (!configured && debug) {
    const missing = [];
    if (!username) missing.push('SMARTBILL_USERNAME');
    if (!token) missing.push('SMARTBILL_TOKEN');
    if (!cif) missing.push('SMARTBILL_CIF');
    if (!series) missing.push('SMARTBILL_SERIES');
    debugLog('Missing SmartBill env vars', missing);
  }
  return configured;
}

function generateCnpControlDigit(first12) {
  const control = '279146358279';
  let sum = 0;
  for (let i = 0; i < 12; i += 1) {
    sum += Number(first12[i]) * Number(control[i]);
  }
  const rest = sum % 11;
  return String(rest === 10 ? 1 : rest);
}

function generateAutoCnp() {
  const sexDigit = Math.random() > 0.5 ? '5' : '6';
  const yy = String(Math.floor(Math.random() * 100)).padStart(2, '0');
  const mm = String(1 + Math.floor(Math.random() * 12)).padStart(2, '0');
  const dd = String(1 + Math.floor(Math.random() * 28)).padStart(2, '0');
  const county = String(1 + Math.floor(Math.random() * 52)).padStart(2, '0');
  const serial = String(1 + Math.floor(Math.random() * 999)).padStart(3, '0');
  const first12 = `${sexDigit}${yy}${mm}${dd}${county}${serial}`;
  return `${first12}${generateCnpControlDigit(first12)}`;
}

export function normalizeBillingTaxCode({ billingType, vatCode }) {
  if (billingType === 'company') {
    return sanitize(vatCode, 64).toUpperCase();
  }
  const fallback = digitsOnly(getSmartbillEnv().individualVatCode) || '0000000000000';
  return fallback;
}

async function smartbillRequest(url, options = {}) {
  const method = options.method || 'GET';
  const bodyPreview =
    typeof options.body === 'string'
      ? options.body.slice(0, 500)
      : options.body;
  debugLog(`Request ${method} ${url}`, bodyPreview);

  let response;
  try {
    response = await fetch(url, options);
  } catch (networkError) {
    throw new Error(`[SmartBill:network] ${networkError.message}`);
  }

  const contentType = response.headers.get('content-type') || '';
  let payload;
  if (contentType.includes('application/json')) {
    payload = await response.json().catch(() => ({}));
  } else {
    payload = await response.text().catch(() => '');
  }
  debugLog(`Response ${method} ${url} -> ${response.status}`, payload);

  if (!response.ok) {
    throw new Error(
      `[SmartBill:http:${response.status}] ${
        typeof payload === 'string' ? payload : JSON.stringify(payload)
      }`,
    );
  }
  return payload;
}

function assertSmartbillSuccess(payload, contextLabel) {
  if (!payload || typeof payload !== 'object') return;
  const errorText = sanitize(payload.errorText || payload.message || '', 800);
  if (errorText) {
    throw new Error(`[SmartBill:${contextLabel}] ${errorText}`);
  }
  const statusCode = Number(payload?.Response?.status?.code);
  if (Number.isFinite(statusCode) && statusCode !== 0) {
    throw new Error(`[SmartBill:${contextLabel}] ${JSON.stringify(payload)}`);
  }
}

function extractInvoiceIdentity(invoiceData = {}) {
  const series =
    sanitize(invoiceData.seriesName || invoiceData.series || invoiceData?.invoice?.seriesName || '');
  const number = sanitize(invoiceData.number || invoiceData?.invoice?.number || '');
  return { series, number };
}

async function createInvoice({
  amount,
  currency = 'RON',
  description,
  billing,
  issueDate,
  dueDate,
}) {
  const { cif, series: seriesNameEnv } = getSmartbillEnv();
  debugLog('Create invoice input', {
    amount: Number(amount || 0),
    currency: sanitize(currency, 8) || 'RON',
    description: sanitize(description || 'Wedding Planner Premium', 180),
    billingType: billing?.type,
    clientName: sanitize(
      billing?.type === 'company'
        ? billing?.company || billing?.name || 'Client'
        : billing?.name || 'Client',
      180,
    ),
    clientCity: sanitize(billing?.city || ''),
    clientVatCode: mask(billing?.vatCode),
    clientEmail: mask(billing?.email),
    clientCounty: sanitize(billing?.county || ''),
    clientRegCom: sanitize(billing?.regNo || ''),
  });

  const payload = {
    companyVatCode: cif,
    client: {
      name: sanitize(
        billing.type === 'company'
          ? billing.company || billing.name || 'Client'
          : billing.name || 'Client',
        180,
      ),
      vatCode: sanitize(billing.vatCode, 64),
      regCom: sanitize(billing.regNo || '', 64),
      isTaxPayer: billing.type === 'company',
      address: sanitize(billing.address || '-'),
      city: sanitize(billing.city || '-'),
      county: sanitize(billing.county || ''),
      country: sanitize(billing.country || 'Romania'),
      email: sanitize(billing.email || ''),
      saveToDb: true,
    },
    issueDate: issueDate || getToday(),
    dueDate: dueDate || addDays(14),
    seriesName: seriesNameEnv,
    isDraft: false,
    currency: sanitize(currency, 8) || 'RON',
    language: 'RO',
    precision: 2,
    products: [
      {
        name: sanitize(description || 'Wedding Planner Premium', 180),
        code: 'WP-PREMIUM',
        isService: true,
        measuringUnitName: 'buc',
        currency: sanitize(currency, 8) || 'RON',
        quantity: 1,
        price: Number(amount || 0),
        isTaxIncluded: true,
        taxPercentage: 19,
        saveToDb: true,
      },
    ],
  };

  const invoiceData = await smartbillRequest(CREATE_INVOICE_URL, {
    method: 'POST',
    headers: {
      Authorization: getAuthHeader(),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });
  assertSmartbillSuccess(invoiceData, 'create-invoice');

  const { series, number } = extractInvoiceIdentity(invoiceData);
  if (!series || !number) {
    throw new Error(`SmartBill invoice identity missing: ${JSON.stringify(invoiceData)}`);
  }

  return { invoiceData, series, number };
}

async function registerPayment({ series, number }) {
  const { cif } = getSmartbillEnv();
  const payload = {
    companyVatCode: cif,
    issueDate: getToday(),
    type: 'Ordin plata',
    isCash: false,
    useInvoiceDetails: true,
    invoicesList: [{ seriesName: series, number }],
  };

  return smartbillRequest(CREATE_PAYMENT_URL, {
    method: 'POST',
    headers: {
      Authorization: getAuthHeader(),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  }).then((result) => {
    assertSmartbillSuccess(result, 'create-payment');
    return result;
  });
}

async function sendInvoiceEmail({ series, number, email }) {
  const { cif, sendEmail } = getSmartbillEnv();
  if (!sendEmail || !email) {
    return {
      skipped: true,
      reason: !sendEmail ? 'disabled_by_env' : 'missing_recipient_email',
    };
  }
  const subject = 'Factura dumneavoastra #serie numar document#';
  const body = `Buna ziua,

Factura dumneavoastra (#serie numar document#), emisa in data de #data emiterii#, este atasata acestui email.

Valoare totala: #total document#.

Daca aveti nevoie de asistenta, ne puteti raspunde direct la acest mesaj.

Multumim,
Echipa WeddingPro`;

  const payload = {
    companyVatCode: cif,
    seriesName: series,
    number,
    type: 'factura',
    subject: toBase64(subject),
    to: sanitize(email, 180),
    bodyText: toBase64(body),
  };

  return smartbillRequest(SEND_DOCUMENT_URL, {
    method: 'POST',
    headers: {
      Authorization: getAuthHeader(),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  }).then((result) => {
    assertSmartbillSuccess(result, 'send-email');
    return result;
  });
}

async function downloadInvoicePdf({ series, number }) {
  const { cif } = getSmartbillEnv();
  const params = new URLSearchParams({
    cif,
    seriesname: series,
    number: String(number),
  });
  const response = await fetch(`${GET_INVOICE_PDF_URL}?${params.toString()}`, {
    method: 'GET',
    headers: {
      Authorization: getAuthHeader(),
    },
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`SmartBill PDF failed (${response.status}): ${text}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  const pdfBuffer = Buffer.from(arrayBuffer);
  const invoicesDir = path.join(process.cwd(), 'uploads', 'smartbill');
  fs.mkdirSync(invoicesDir, { recursive: true });
  const filename = `factura-${sanitize(series, 50)}-${sanitize(number, 50)}.pdf`;
  const filePath = path.join(invoicesDir, filename);
  fs.writeFileSync(filePath, pdfBuffer);
  return {
    filename,
    filePath,
    publicUrl: `/uploads/smartbill/${filename}`,
  };
}

export async function createSmartbillInvoiceFlow({
  billing,
  amount,
  currency = 'RON',
  description = 'Wedding Planner Premium',
  issueDate,
  dueDate,
  sendEmail = true,
}) {
  debugLog('SmartBill flow start', {
    amount: Number(amount || 0),
    currency,
    sendEmail,
    description,
    configured: smartbillConfigured(),
  });

  if (!smartbillConfigured()) {
    return { enabled: false };
  }

  const normalizedBilling = {
    ...billing,
    vatCode: normalizeBillingTaxCode({
      billingType: billing.type === 'company' ? 'company' : 'individual',
      vatCode: billing.vatCode,
    }),
  };

  const { invoiceData, series, number } = await createInvoice({
    amount,
    currency,
    description,
    billing: normalizedBilling,
    issueDate,
    dueDate,
  });

  const paymentData = await registerPayment({ series, number });
  const emailData = sendEmail
    ? await sendInvoiceEmail({ series, number, email: normalizedBilling.email })
    : { skipped: true, reason: 'disabled_by_function_param' };
  const pdf = await downloadInvoicePdf({ series, number });

  debugLog('SmartBill flow completed', {
    invoiceNumber: `${series}-${number}`,
    pdfPublicUrl: pdf.publicUrl,
    emailSent: !emailData?.skipped,
    emailSkipReason: emailData?.reason || '',
    clientTaxCode: mask(normalizedBilling.vatCode),
    smartbillUser: mask(getSmartbillEnv().username),
    smartbillCif: getSmartbillEnv().cif,
    smartbillSeries: getSmartbillEnv().series,
  });

  return {
    enabled: true,
    series,
    number,
    invoiceNumber: `${series}-${number}`,
    pdfPublicUrl: pdf.publicUrl,
    pdfFilePath: pdf.filePath,
    pdfFileName: pdf.filename,
    invoiceData,
    paymentData,
    emailData,
    clientTaxCode: normalizedBilling.vatCode,
  };
}

export const isSmartbillConfigured = smartbillConfigured;
