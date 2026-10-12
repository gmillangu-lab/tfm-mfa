/**
 * Utilidad de Generación de Huella de Dispositivo (Device Fingerprinting)
 * Cumplimiento de Privacidad por Diseño (Art. 25 RGPD):
 * - No recopila direcciones IP.
 * - No almacena cookies de seguimiento de terceros ni identificadores permanentes de hardware (como MAC o IMEI).
 * - Utiliza una función resumen criptográfica unidireccional SHA-256 sobre componentes de renderizado y navegador.
 */

export async function generateDeviceFingerprint(customSalt = '') {
  const nav = typeof window !== 'undefined' ? window.navigator : {};
  const scr = typeof window !== 'undefined' ? window.screen : {};

  // Componentes de entropía del cliente
  const components = {
    userAgent: nav.userAgent || 'unknown_ua',
    language: nav.language || 'es-ES',
    platform: nav.platform || 'unknown_platform',
    screenResolution: `${scr.width || 0}x${scr.height || 0}`,
    colorDepth: scr.colorDepth || 24,
    deviceMemory: nav.deviceMemory || 8,
    hardwareConcurrency: nav.hardwareConcurrency || 4,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    customSalt
  };

  const rawString = Object.entries(components)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

  // Cálculo del hash SHA-256 mediante Web Crypto API
  let hashHex = '';
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(rawString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    // Fallback simple si Web Crypto no estuviera disponible
    let simpleHash = 0;
    for (let i = 0; i < rawString.length; i++) {
      simpleHash = (simpleHash << 5) - simpleHash + rawString.charCodeAt(i);
      simpleHash |= 0;
    }
    hashHex = Math.abs(simpleHash).toString(16).padStart(64, '0');
  }

  // Parsear una descripción amigable sin datos personales
  let os = 'OS Desconocido';
  if (/Windows/i.test(components.userAgent)) os = 'Windows';
  else if (/Macintosh|Mac OS/i.test(components.userAgent)) os = 'macOS';
  else if (/Linux/i.test(components.userAgent)) os = 'Linux';
  else if (/Android/i.test(components.userAgent)) os = 'Android';
  else if (/iPhone|iPad/i.test(components.userAgent)) os = 'iOS';

  let browser = 'Navegador Web';
  if (/Edg/i.test(components.userAgent)) browser = 'Edge';
  else if (/Chrome/i.test(components.userAgent)) browser = 'Chrome';
  else if (/Firefox/i.test(components.userAgent)) browser = 'Firefox';
  else if (/Safari/i.test(components.userAgent)) browser = 'Safari';

  const friendlySummary = `${os} · ${browser} (${components.screenResolution})`;
  const anonymizedDisplay = `fp_${hashHex.substring(0, 6)}...${hashHex.substring(hashHex.length - 4)}`;

  return {
    rawHash: hashHex,
    anonymizedDisplay,
    friendlySummary,
    entropyComponents: {
      screenResolution: components.screenResolution,
      timezone: components.timezone,
      language: components.language,
      platform: components.platform
    }
  };
}
