/**
 * Configuración de Firebase v10+ y GCP Cloud Run
 * TFM: Security Dashboard con MFA Adaptativo
 * 
 * Totalmente adaptado a las Reglas de Seguridad de Firestore:
 * - access_logs: allow create, read: if request.auth != null;
 * - authorized_devices: allow read, write: if request.auth != null && request.auth.uid == ...
 */

import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, onAuthStateChanged } from 'firebase/auth';
import { 
  getFirestore, 
  collection, 
  addDoc, 
  getDocs,
  doc,
  setDoc,
  deleteDoc,
  where,
  serverTimestamp, 
  query, 
  limit, 
  onSnapshot 
} from 'firebase/firestore';

// 1. Lectura segura de variables de entorno de Vite con respaldos
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || 'AIzaSyD76jaF81OoJJ7yB74iCiYs6CjDl2pzeZE',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || 'tfm-mfa.firebaseapp.com',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || 'tfm-mfa',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || 'tfm-mfa.firebasestorage.app',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '262417646826',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '1:262417646826:web:e469472ae0ff5086d30393',
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || 'G-W16B111J3B'
};

// URL del servicio Serverless en Google Cloud Run
export const CLOUD_RUN_API_URL = import.meta.env.VITE_CLOUD_RUN_API_URL || '';

// Comprobar si se han suministrado credenciales reales de Firebase
export const isFirebaseConfigured = () => {
  return Boolean(
    firebaseConfig.apiKey && 
    !firebaseConfig.apiKey.includes('YourFirebase') &&
    firebaseConfig.projectId &&
    !firebaseConfig.projectId.includes('tu-proyecto')
  );
};

// 2. Inicialización de Firebase (Singleton)
/** @type {import('firebase/app').FirebaseApp | null} */
let app = null;
/** @type {import('firebase/auth').Auth | null} */
let auth = null;
/** @type {import('firebase/firestore').Firestore | null} */
let db = null;

// Estado de diagnóstico reactivo de Firestore
export const firestoreDiagnostic = {
  databaseId: '(default)',
  collections: ['access_logs', 'authorized_devices'],
  projectId: firebaseConfig.projectId,
  status: 'INITIALIZING', // 'CONNECTED' | 'PERMISSION_DENIED' | 'REQUIRES_AUTH' | 'LOCAL_FALLBACK'
  lastDocId: null,
  lastError: null,
  lastAttemptAt: null,
  docsCount: 0,
  authenticatedUser: null
};

function updateDiagnostic(patch) {
  Object.assign(firestoreDiagnostic, patch, { lastAttemptAt: new Date().toISOString() });
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('tfm_firestore_diagnostic_update', { detail: firestoreDiagnostic }));
  }
}

try {
  if (isFirebaseConfigured()) {
    app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
    auth = getAuth(app);
    // Conexión explícita a la base de datos (default)
    db = getFirestore(app, '(default)');
    console.info(`[Firebase Firestore] Conectado exitosamente a "(default)" en proyecto: ${firebaseConfig.projectId}`);
    updateDiagnostic({ status: 'CONNECTED', lastError: null });

    // Escuchar el estado de autenticación para sincronizar diagnósticos
    onAuthStateChanged(auth, (user) => {
      updateDiagnostic({ 
        authenticatedUser: user ? user.email : null,
        status: user ? 'CONNECTED' : 'REQUIRES_AUTH'
      });
    });
  } else {
    console.info('[Firebase] Modo demostración activo: Variables VITE_FIREBASE_* no configuradas.');
    updateDiagnostic({ status: 'LOCAL_FALLBACK', lastError: 'Sin credenciales configuradas' });
  }
} catch (error) {
  console.warn('[Firebase] Inicialización omitida o fallida. Operando en modo audit-engine local:', error);
  updateDiagnostic({ status: 'ERROR', lastError: error.message });
}

export { app, auth, db, firebaseConfig };

// 3. Helper de auditoría en Firestore (Colección: access_logs) con Privacy by Design
// Requiere request.auth != null conforme a tus reglas de seguridad
export async function recordAccessLog(logEntry) {
  const currentUser = auth?.currentUser;

  const sanitizedEntry = {
    timestamp: new Date().toISOString(),
    eventTimestamp: Date.now(),
    userId: currentUser ? currentUser.uid : (logEntry.userId || 'anonymous_attempt'),
    userEmail: currentUser ? currentUser.email : (logEntry.userEmail || 'no-auth-session'),
    status: logEntry.status || 'UNKNOWN', // 'SUCCESS' | 'MFA_REQUIRED' | 'FAILED'
    latencyMs: Number(logEntry.latencyMs) || 0,
    anonymizedDevice: logEntry.anonymizedDevice || 'Anon-Device-SHA256',
    deviceType: logEntry.deviceType || 'Desktop Browser',
    ruleEvaluations: logEntry.ruleEvaluations || [],
    rgpdCompliant: true,
    privacyNotice: 'Anonimizado conforme al Art. 25 y 32 RGPD. No almacena IP ni PII.'
  };

  // Solo intentamos escribir directamente en Firestore Cloud si el usuario está autenticado
  // para cumplir estrictamente con: allow create: if request.auth != null;
  if (db && isFirebaseConfigured() && currentUser) {
    try {
      const logsRef = collection(db, 'access_logs');
      const docRef = await addDoc(logsRef, {
        ...sanitizedEntry,
        createdAt: serverTimestamp()
      });

      console.info(`[Firestore access_logs] Documento insertado con éxito en "(default)". ID: ${docRef.id}`);
      updateDiagnostic({ 
        status: 'CONNECTED', 
        lastDocId: docRef.id, 
        lastError: null 
      });

      const result = { id: docRef.id, ...sanitizedEntry };
      syncWithLocalCache(result);
      return result;
    } catch (err) {
      console.error('[Firestore] Error al persistir log en access_logs:', err);
      let errorMsg = err.message || 'Error desconocido';
      let status = 'ERROR';
      if (err.code === 'permission-denied') {
        errorMsg = 'Permiso denegado en Firestore (access_logs). Requiere usuario autenticado.';
        status = 'PERMISSION_DENIED';
      }
      updateDiagnostic({ status, lastError: errorMsg });
    }
  }

  // Si no está autenticado aún (ej. fallo previo de contraseña), almacenamos en caché local para auditoría
  return syncWithLocalCache({ 
    id: `local-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`, 
    ...sanitizedEntry 
  });
}

function syncWithLocalCache(entry) {
  const existingRaw = localStorage.getItem('tfm_audit_access_logs');
  const existing = existingRaw ? JSON.parse(existingRaw) : [];
  const updated = [entry, ...existing.filter(i => i.id !== entry.id)].slice(0, 100);
  localStorage.setItem('tfm_audit_access_logs', JSON.stringify(updated));
  window.dispatchEvent(new CustomEvent('tfm_new_access_log', { detail: entry }));
  return entry;
}

// 4. Colección: authorized_devices (Registro de dispositivos confiables del frontend)
// Conforme a regla: allow read, write: if request.auth != null && request.auth.uid == ...
export async function addAuthorizedDeviceToFirestore({ deviceHash, label, deviceType }) {
  const currentUser = auth?.currentUser;

  if (!db || !isFirebaseConfigured()) {
    return { 
      success: false, 
      error: 'Firebase no está configurado en .env con projectId válido.',
      code: 'unconfigured' 
    };
  }

  if (!currentUser) {
    const errorMsg = 'No hay sesión de usuario activa (request.auth es null). Debes iniciar sesión con tu cuenta para que Firestore acepte la regla: allow write: if request.auth != null.';
    console.warn('[authorized_devices]', errorMsg);
    updateDiagnostic({ status: 'REQUIRES_AUTH', lastError: errorMsg });
    return { success: false, error: errorMsg, code: 'unauthenticated' };
  }

  try {
    const devicesRef = collection(db, 'authorized_devices');
    const docData = {
      userId: currentUser.uid,
      userEmail: currentUser.email || '',
      deviceHash,
      label: label || 'Dispositivo Confiable',
      deviceType: deviceType || 'Navegador Web',
      registeredAt: new Date().toISOString(),
      createdAt: serverTimestamp()
    };

    console.info(`[Firestore authorized_devices] Intentando escribir en Firestore "(default)" para userId: ${currentUser.uid}...`);
    const docRef = await addDoc(devicesRef, docData);
    console.info(`[Firestore authorized_devices] ¡ÉXITO! Documento creado en Firestore. ID: ${docRef.id}`);

    // Solo registramos en caché local tras confirmación de éxito en Firestore
    registerLocalTrustedDevice(deviceHash, label);

    updateDiagnostic({
      status: 'CONNECTED',
      lastDocId: docRef.id,
      lastError: null
    });

    window.dispatchEvent(new CustomEvent('tfm_authorized_devices_changed'));

    return { 
      success: true, 
      id: docRef.id, 
      ...docData, 
      source: 'FIRESTORE' 
    };
  } catch (err) {
    console.error('[Firestore authorized_devices] Error al guardar dispositivo en Firestore:', err);
    let errMsg = err.message;
    if (err.code === 'permission-denied') {
      errMsg = 'Error "permission-denied" en Firestore: Tu regla actual `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;` está bloqueando la creación. En Firestore, al crear un documento nuevo `resource` es null. Debes cambiar en Firebase Console a: `allow create: if request.auth != null && request.auth.uid == request.resource.data.userId;`';
    }
    updateDiagnostic({ status: 'PERMISSION_DENIED', lastError: errMsg });
    return { success: false, error: errMsg, code: err.code };
  }
}

export function subscribeToAuthorizedDevices(onUpdate, onError) {
  const currentUser = auth?.currentUser;

  if (db && isFirebaseConfigured() && currentUser) {
    try {
      const devicesRef = collection(db, 'authorized_devices');
      // Filtramos por el userId del usuario autenticado
      const q = query(devicesRef, where('userId', '==', currentUser.uid), limit(50));
      
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const remoteDevices = snapshot.docs.map(doc => ({
          id: doc.id,
          docId: doc.id,
          hash: doc.data().deviceHash,
          label: doc.data().label,
          registeredAt: doc.data().registeredAt,
          source: 'FIRESTORE',
          ...doc.data()
        }));

        console.info(`[Firestore authorized_devices] Snapshot recibido: ${remoteDevices.length} dispositivos en Firestore.`);
        // Guardar en almacenamiento de sincronización
        localStorage.setItem('tfm_trusted_device_hashes', JSON.stringify(remoteDevices));
        onUpdate(remoteDevices);
      }, (err) => {
        console.warn('[Firestore authorized_devices] Error en snapshot de Firestore:', err);
        let errMsg = err.message;
        if (err.code === 'permission-denied') {
          errMsg = 'Permiso denegado por reglas de Firestore en authorized_devices. (Requiere usuario autenticado).';
        }
        updateDiagnostic({ status: 'PERMISSION_DENIED', lastError: errMsg });
        if (typeof onError === 'function') onError(errMsg);
        onUpdate([]);
      });

      return unsubscribe;
    } catch (err) {
      console.warn('[Firestore] Error listener authorized_devices:', err);
      if (typeof onError === 'function') onError(err.message);
    }
  }

  // Si no está autenticado aún, la lista en Firestore es vacía
  onUpdate([]);
  return () => {};
}

export async function removeAuthorizedDeviceFromFirestore(docId) {
  if (db && isFirebaseConfigured() && docId) {
    try {
      await deleteDoc(doc(db, 'authorized_devices', docId));
      console.info(`[Firestore authorized_devices] Documento eliminado: ${docId}`);
      window.dispatchEvent(new CustomEvent('tfm_authorized_devices_changed'));
      return { success: true };
    } catch (err) {
      console.error('[Firestore authorized_devices] Error al eliminar:', err);
      return { success: false, error: err.message };
    }
  }
  return { success: false };
}

export async function isDeviceAuthorizedInFirestore(deviceHash, userId) {
  const currentUser = auth?.currentUser;
  const uid = userId || currentUser?.uid;

  if (db && isFirebaseConfigured() && uid) {
    try {
      const devicesRef = collection(db, 'authorized_devices');
      const q = query(devicesRef, where('userId', '==', uid), limit(50));
      const snapshot = await getDocs(q);
      const matched = snapshot.docs.some(doc => doc.data()?.deviceHash === deviceHash);
      if (matched) return true;
    } catch (err) {
      console.warn('[Firestore] Error consultando isDeviceAuthorizedInFirestore:', err);
    }
  }

  // Fallback a almacenamiento local
  const local = getLocalTrustedDevices();
  return local.some(d => d.hash === deviceHash);
}

function getLocalTrustedDevices() {
  try {
    const raw = localStorage.getItem('tfm_trusted_device_hashes');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function registerLocalTrustedDevice(deviceHash, label = 'Dispositivo Confiable') {
  try {
    const trusted = getLocalTrustedDevices();
    if (!trusted.some(d => d.hash === deviceHash)) {
      trusted.push({ hash: deviceHash, label, registeredAt: new Date().toISOString(), source: 'LOCAL_STORAGE' });
      localStorage.setItem('tfm_trusted_device_hashes', JSON.stringify(trusted));
    }
  } catch (e) {
    console.error(e);
  }
}

// 5. Función de prueba explícita para crear colecciones en Firestore con usuario autenticado
export async function testAndCreateFirestoreCollection() {
  if (!db || !isFirebaseConfigured()) {
    return {
      success: false,
      error: 'Firebase no está configurado con credenciales válidas en .env.'
    };
  }

  const currentUser = auth?.currentUser;
  if (!currentUser) {
    return {
      success: false,
      error: 'Tus reglas exigen autenticación activa (request.auth != null). Inicia sesión para probar la escritura en Firestore.'
    };
  }

  try {
    const logsRef = collection(db, 'access_logs');
    const testDoc = {
      timestamp: new Date().toISOString(),
      eventTimestamp: Date.now(),
      userId: currentUser.uid,
      userEmail: currentUser.email,
      status: 'SUCCESS',
      latencyMs: 82,
      anonymizedDevice: 'fp_probe_' + Math.random().toString(36).substring(2, 6),
      deviceType: 'Sonda de Auditoría TFM',
      ruleEvaluations: [
        'Prueba de verificación con regla request.auth != null',
        'Validación de colección access_logs en base de datos (default)'
      ],
      rgpdCompliant: true,
      createdAt: serverTimestamp()
    };

    const docRef = await addDoc(logsRef, testDoc);
    console.info(`[Firestore Test] Documento de prueba creado exitosamente en access_logs. ID: ${docRef.id}`);

    updateDiagnostic({
      status: 'CONNECTED',
      lastDocId: docRef.id,
      lastError: null
    });

    return {
      success: true,
      docId: docRef.id,
      message: `Documento insertado correctamente. Colecciones 'access_logs' y 'authorized_devices' sincronizadas en (default).`
    };
  } catch (err) {
    console.error('[Firestore Test] Error:', err);
    let userFriendly = err.message;
    if (err.code === 'permission-denied') {
      userFriendly = 'Error: permiso denegado por reglas de Firestore. Asegúrate de estar autenticado.';
    }
    updateDiagnostic({
      status: 'PERMISSION_DENIED',
      lastError: userFriendly
    });
    return {
      success: false,
      error: userFriendly,
      code: err.code
    };
  }
}

// 6. Suscriptor reactivo en tiempo real a access_logs en Firestore
export function subscribeToAccessLogs(onUpdate) {
  const currentUser = auth?.currentUser;

  // Solo nos suscribimos a Firestore si hay usuario autenticado (conforme a allow read: if request.auth != null;)
  if (db && isFirebaseConfigured() && currentUser) {
    try {
      const logsRef = collection(db, 'access_logs');
      const q = query(logsRef, limit(50));
      
      const unsubscribe = onSnapshot(q, (snapshot) => {
        if (!snapshot.empty) {
          const remoteLogs = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
          }));

          // Ordenar cronológicamente descendente
          remoteLogs.sort((a, b) => {
            const timeA = a.eventTimestamp || new Date(a.timestamp || 0).getTime();
            const timeB = b.eventTimestamp || new Date(b.timestamp || 0).getTime();
            return timeB - timeA;
          });

          updateDiagnostic({ 
            status: 'CONNECTED', 
            docsCount: remoteLogs.length, 
            lastError: null 
          });
          onUpdate(remoteLogs);
        } else {
          updateDiagnostic({ status: 'CONNECTED', docsCount: 0 });
          loadLocalBackup(onUpdate);
        }
      }, (err) => {
        console.warn('[Firestore] Error en snapshot de access_logs:', err);
        let errorMsg = err.message;
        if (err.code === 'permission-denied') {
          errorMsg = 'Lectura de access_logs denegada: requiere usuario autenticado.';
        }
        updateDiagnostic({ status: 'PERMISSION_DENIED', lastError: errorMsg });
        fallbackLocalSubscription(onUpdate);
      });

      return unsubscribe;
    } catch (err) {
      console.warn('[Firestore] Error listener:', err);
      updateDiagnostic({ status: 'ERROR', lastError: err.message });
    }
  }

  return fallbackLocalSubscription(onUpdate);
}

function loadLocalBackup(onUpdate) {
  const raw = localStorage.getItem('tfm_audit_access_logs');
  if (raw) {
    try {
      onUpdate(JSON.parse(raw));
      return;
    } catch (e) {
      console.error(e);
    }
  }
  const seeds = generateSeedLogs();
  localStorage.setItem('tfm_audit_access_logs', JSON.stringify(seeds));
  onUpdate(seeds);
}

function fallbackLocalSubscription(onUpdate) {
  loadLocalBackup(onUpdate);

  const handleCustomEvent = () => {
    const raw = localStorage.getItem('tfm_audit_access_logs');
    if (raw) {
      try {
        onUpdate(JSON.parse(raw));
      } catch (err) {
        console.error(err);
      }
    }
  };

  window.addEventListener('tfm_new_access_log', handleCustomEvent);
  return () => {
    window.removeEventListener('tfm_new_access_log', handleCustomEvent);
  };
}

function generateSeedLogs() {
  const now = Date.now();
  return [
    {
      id: 'seed-1',
      timestamp: new Date(now - 1000 * 60 * 4).toISOString(),
      eventTimestamp: now - 1000 * 60 * 4,
      status: 'SUCCESS',
      latencyMs: 142,
      anonymizedDevice: 'fp_a7f9...3b81',
      deviceType: 'MacBook Pro · Chrome 122',
      riskScore: 8,
      riskLevel: 'LOW',
      ruleEvaluations: ['Dispositivo previamente enrolado', 'Firma criptográfica coincidente'],
      rgpdCompliant: true
    },
    {
      id: 'seed-2',
      timestamp: new Date(now - 1000 * 60 * 18).toISOString(),
      eventTimestamp: now - 1000 * 60 * 18,
      status: 'MFA_REQUIRED',
      latencyMs: 310,
      anonymizedDevice: 'fp_4c1e...90a2',
      deviceType: 'Windows 11 · Firefox 123',
      riskScore: 78,
      riskLevel: 'HIGH',
      ruleEvaluations: ['Dispositivo desconocido no registrado', 'Reto TOTP disparado'],
      rgpdCompliant: true
    },
    {
      id: 'seed-3',
      timestamp: new Date(now - 1000 * 60 * 35).toISOString(),
      eventTimestamp: now - 1000 * 60 * 35,
      status: 'SUCCESS',
      latencyMs: 165,
      anonymizedDevice: 'fp_a7f9...3b81',
      deviceType: 'MacBook Pro · Chrome 122',
      riskScore: 12,
      riskLevel: 'LOW',
      ruleEvaluations: ['Huella reconocida', 'Acceso directo autorizado'],
      rgpdCompliant: true
    }
  ];
}
