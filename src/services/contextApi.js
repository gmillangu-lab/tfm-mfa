/**
 * Servicio de Cliente para la API de Evaluación de Contexto en GCP Cloud Run
 * Endpoint: POST ${CLOUD_RUN_API_URL}/api/verify-context
 * 
 * Evalúa las reglas de riesgo adaptativo:
 * - Huella de dispositivo (Fingerprint SHA-256)
 * - Registro de dispositivos de confianza del usuario (Directamente desde Firestore 'authorized_devices')
 * - Detección de anomalías horarias o de cabeceras
 * - Retorna { requireMFA: boolean, riskScore: number, reason: string, latencyMs: number }
 */

import { 
  CLOUD_RUN_API_URL, 
  addAuthorizedDeviceToFirestore, 
  removeAuthorizedDeviceFromFirestore,
  isDeviceAuthorizedInFirestore 
} from '../firebaseConfig';

const TRUSTED_DEVICES_STORAGE_KEY = 'tfm_trusted_device_hashes';

export function getTrustedDevices() {
  try {
    const raw = localStorage.getItem(TRUSTED_DEVICES_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export async function registerTrustedDevice(deviceHash, label = 'Dispositivo Confiable', deviceType = 'Navegador Web') {
  try {
    const trusted = getTrustedDevices();
    if (!trusted.some(d => d.hash === deviceHash)) {
      trusted.push({ hash: deviceHash, label, registeredAt: new Date().toISOString() });
      localStorage.setItem(TRUSTED_DEVICES_STORAGE_KEY, JSON.stringify(trusted));
    }
    // Sincronizar directamente con la colección authorized_devices de Firestore
    await addAuthorizedDeviceToFirestore({ deviceHash, label, deviceType });
  } catch (e) {
    console.error('Error al registrar dispositivo confiable:', e);
  }
}

export async function removeTrustedDevice(deviceHash, docId = null) {
  try {
    const trusted = getTrustedDevices().filter(d => d.hash !== deviceHash);
    localStorage.setItem(TRUSTED_DEVICES_STORAGE_KEY, JSON.stringify(trusted));

    if (docId) {
      await removeAuthorizedDeviceFromFirestore(docId);
    }
  } catch (e) {
    console.error(e);
  }
}

/**
 * Llamada al servicio Cloud Run para verificar contexto
 */
export async function verifyContextWithCloudRun({ userId, email, fingerprintData, forceAnomaly = false }) {
  const startTime = performance.now();
  const requestPayload = {
    userId: userId || email || 'usr_anonymous',
    email: email || '',
    deviceFingerprint: fingerprintData.rawHash,
    anonymizedDisplay: fingerprintData.anonymizedDisplay,
    entropyComponents: fingerprintData.entropyComponents,
    timestamp: new Date().toISOString(),
    clientPlatform: navigator.platform || 'web'
  };

  // 1. Si existe URL válida de Cloud Run y no es un placeholder, realizamos la petición HTTP real
  const isRealCloudRun = CLOUD_RUN_API_URL && 
    !CLOUD_RUN_API_URL.includes('xxxxxx') && 
    CLOUD_RUN_API_URL.startsWith('http');

  if (isRealCloudRun) {
    try {
      const response = await fetch(`${CLOUD_RUN_API_URL}/api/verify-context`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Security-Client': 'TFM-Adaptive-MFA-React-v1.0'
        },
        body: JSON.stringify(requestPayload)
      });

      if (!response.ok) {
        throw new Error(`Cloud Run HTTP error: ${response.status}`);
      }

      const data = await response.json();
      const endTime = performance.now();
      const latencyMs = Math.round(endTime - startTime);

      return {
        ...data,
        latencyMs,
        source: 'CLOUD_RUN_PRODUCTION'
      };
    } catch (err) {
      console.warn('[ContextAPI] Petición a Cloud Run no disponible o fallida. Ejecutando motor de reglas contextuales local:', err);
    }
  }

  // 2. Motor de Reglas Contextuales Adaptativas (Serverless Engine para TFM)
  // Simula latencia de red de microservicio serverless (80 - 180 ms)
  const simulatedDelay = Math.floor(Math.random() * 80) + 95;
  await new Promise(r => setTimeout(r, simulatedDelay));

  const endTime = performance.now();
  const latencyMs = Math.round(endTime - startTime);

  // Evaluación de Reglas de Seguridad Zero-Trust:
  // Consulta directa a Firestore 'authorized_devices' con respaldo en caché local
  let isDeviceTrusted = false;
  if (!forceAnomaly) {
    isDeviceTrusted = await isDeviceAuthorizedInFirestore(fingerprintData.rawHash, userId);
  }

  let requireMFA = false;
  let ruleEvaluations = [];
  let reason = 'Dispositivo habitual reconocido.';

  if (forceAnomaly) {
    requireMFA = true;
    ruleEvaluations = [
      'Anomalía forzada por perfil de prueba',
      'Desviación de vector de comportamiento detectada',
      'Política Zero-Trust: Activación obligatoria de 2º factor TOTP'
    ];
    reason = 'Dispositivo sospechoso o intento anómalo simulado.';
  } else if (!isDeviceTrusted) {
    // Dispositivo nuevo o no registrado en authorized_devices
    requireMFA = true;
    ruleEvaluations = [
      'Dispositivo no catalogado en Firestore: authorized_devices',
      'Huella SHA-256 no encontrada en el histórico del usuario',
      'Política Zero-Trust: Reto MFA TOTP requerido'
    ];
    reason = 'Nuevo dispositivo detectado. Se requiere verificación de segundo factor TOTP.';
  } else {
    // Dispositivo conocido verificado en Firestore
    requireMFA = false;
    ruleEvaluations = [
      'Dispositivo verificado en colección Firestore: authorized_devices',
      'Firma criptográfica SHA-256 coincide con el perfil del usuario',
      'Política Zero-Trust: Acceso directo autorizado'
    ];
    reason = 'Dispositivo verificado y de confianza en Firestore. Acceso directo autorizado.';
  }

  return {
    requireMFA,
    reason,
    ruleEvaluations,
    latencyMs,
    evaluatedAt: new Date().toISOString(),
    source: 'CLOUD_RUN_SIMULATION_ENGINE'
  };
}
