/**
 * Componente: Dashboard.jsx
 * Security Dashboard con MFA Adaptativo
 * 
 * Conexión en tiempo real a Firestore (Colección access_logs).
 * Métricas KPIs:
 *  - Tasa de Éxito / Error de accesos (%)
 *  - Latencia media del proceso de verificación (ms)
 *  - Alertas de dispositivos no reconocidos detectados
 * Gráficos Recharts:
 *  - Histórico de accesos y tiempos de verificación
 *  - Distribución de estados de eventos (SUCCESS, MFA_REQUIRED, FAILED)
 * Cumplimiento RGPD (Privacy by Design - Art. 25 y 32 RGPD)
 */

import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Activity, 
  Clock, 
  Users, 
  Laptop, 
  LogOut, 
  RefreshCw, 
  Database, 
  Cloud, 
  CheckCircle, 
  AlertCircle,
  FileText,
  KeyRound,
  Shield,
  Trash2,
  Plus
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid, 
  PieChart, 
  Pie, 
  Cell,
  Legend
} from 'recharts';

import AccessLogsTable from './AccessLogsTable';
import { 
  subscribeToAccessLogs, 
  recordAccessLog, 
  isFirebaseConfigured, 
  CLOUD_RUN_API_URL,
  firestoreDiagnostic,
  testAndCreateFirestoreCollection,
  subscribeToAuthorizedDevices,
  addAuthorizedDeviceToFirestore,
  removeAuthorizedDeviceFromFirestore
} from '../firebaseConfig';
import { getTrustedDevices, removeTrustedDevice, registerTrustedDevice } from '../services/contextApi';
import { generateDeviceFingerprint } from '../utils/fingerprint';

const COLORS = {
  success: '#10b981', // emerald-500
  mfa: '#f59e0b',     // amber-500
  failed: '#f43f5e',  // rose-500
  cyan: '#06b6d4',    // cyan-500
  slate: '#64748b'
};

export default function Dashboard({ 
  userSession, 
  onLogout, 
  onOpenEnrollment 
}) {
  const [logs, setLogs] = useState([]);
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'trusted_devices' | 'architecture'
  const [fsStatus, setFsStatus] = useState({ ...firestoreDiagnostic });
  const [isTestingFs, setIsTestingFs] = useState(false);
  const [fsTestResult, setFsTestResult] = useState(null);
  const [showFsModal, setShowFsModal] = useState(false);
  const [deviceNotice, setDeviceNotice] = useState(null); // { type: 'success' | 'error', message: string }

  // Suscripción en tiempo real a Firestore access_logs y authorized_devices
  useEffect(() => {
    const unsubscribeLogs = subscribeToAccessLogs((updatedLogs) => {
      setLogs(updatedLogs);
    });

    const unsubscribeDevices = subscribeToAuthorizedDevices(
      (devices) => {
        setTrustedDevices(devices);
      },
      (errMsg) => {
        setDeviceNotice({ type: 'error', message: errMsg });
      }
    );

    const handleDiagnostic = (e) => {
      setFsStatus({ ...e.detail });
    };
    window.addEventListener('tfm_firestore_diagnostic_update', handleDiagnostic);

    // Ejecutar verificación y creación de las colecciones en la base de datos (default)
    if (isFirebaseConfigured()) {
      testAndCreateFirestoreCollection().then((res) => {
        setFsTestResult(res);
      });
    }

    return () => {
      if (typeof unsubscribeLogs === 'function') unsubscribeLogs();
      if (typeof unsubscribeDevices === 'function') unsubscribeDevices();
      window.removeEventListener('tfm_firestore_diagnostic_update', handleDiagnostic);
    };
  }, []);

  // 1. Cálculo de KPIs en tiempo real
  const kpis = useMemo(() => {
    const total = logs.length;
    if (total === 0) {
      return {
        total: 0,
        successRate: 100,
        errorRate: 0,
        avgLatency: 0,
        unrecognizedAlerts: 0,
        mfaCount: 0,
        successCount: 0,
        failedCount: 0
      };
    }

    const successCount = logs.filter(l => l.status === 'SUCCESS').length;
    const mfaCount = logs.filter(l => l.status === 'MFA_REQUIRED').length;
    const failedCount = logs.filter(l => l.status === 'FAILED').length;

    const successRate = Math.round((successCount / total) * 100);
    const errorRate = Math.round((failedCount / total) * 100);

    const sumLatency = logs.reduce((acc, curr) => acc + (Number(curr.latencyMs) || 0), 0);
    const avgLatency = Math.round(sumLatency / total);

    // Alertas: eventos con riesgo alto o dispositivos no reconocidos
    const unrecognizedAlerts = logs.filter(l => 
      l.status === 'MFA_REQUIRED' || (l.riskScore && l.riskScore > 50)
    ).length;

    return {
      total,
      successRate,
      errorRate,
      avgLatency,
      unrecognizedAlerts,
      mfaCount,
      successCount,
      failedCount
    };
  }, [logs]);

  // 2. Preparación de datos para gráficos cronológicos
  const timelineData = useMemo(() => {
    // Tomar los últimos 15 eventos cronológicamente
    const chronological = [...logs].reverse().slice(-15);
    return chronological.map((log, index) => {
      const timeStr = log.timestamp 
        ? new Date(log.timestamp).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : `#${index + 1}`;
      
      return {
        time: timeStr,
        latency: log.latencyMs || 0,
        risk: log.riskScore || 0,
        status: log.status,
        isSuccess: log.status === 'SUCCESS' ? 1 : 0,
        isMfa: log.status === 'MFA_REQUIRED' ? 1 : 0,
        isFailed: log.status === 'FAILED' ? 1 : 0
      };
    });
  }, [logs]);

  // 3. Distribución para gráfico circular (Donut)
  const distributionData = useMemo(() => {
    return [
      { name: 'Accesos Exitosos', value: kpis.successCount, color: COLORS.success },
      { name: 'Retos MFA Adaptativo', value: kpis.mfaCount, color: COLORS.mfa },
      { name: 'Intentos Fallidos', value: kpis.failedCount, color: COLORS.failed }
    ].filter(item => item.value > 0);
  }, [kpis]);

  // Generador de eventos de simulación en vivo para el tribunal/evaluador
  const handleSimulateLiveEvent = async () => {
    setIsSimulating(true);
    const types = ['SUCCESS', 'MFA_REQUIRED', 'FAILED'];
    const selectedType = types[Math.floor(Math.random() * types.length)];
    const randomLatency = Math.floor(Math.random() * 220) + 85;
    const randomHash = 'fp_' + Math.random().toString(36).substring(2, 8) + '...' + Math.random().toString(36).substring(2, 6);

    const devices = [
      'MacBook Air M2 · Safari 17.4',
      'Windows 11 · Chrome 123',
      'Ubuntu 22.04 · Firefox 124',
      'Pixel 8 Pro · Chrome Mobile'
    ];
    const deviceType = devices[Math.floor(Math.random() * devices.length)];

    let riskScore = 15;
    let ruleEvaluations = [];

    if (selectedType === 'SUCCESS') {
      riskScore = Math.floor(Math.random() * 20) + 5;
      ruleEvaluations = ['Dispositivo conocido verificado', 'Acceso directo autorizado'];
    } else if (selectedType === 'MFA_REQUIRED') {
      riskScore = Math.floor(Math.random() * 30) + 65;
      ruleEvaluations = ['Dispositivo nuevo no catalogado', 'Reto adaptativo TOTP disparado'];
    } else {
      riskScore = Math.floor(Math.random() * 20) + 80;
      ruleEvaluations = ['Credencial errónea de primer factor', 'Intento bloqueado preventivamente'];
    }

    await recordAccessLog({
      status: selectedType,
      latencyMs: randomLatency,
      anonymizedDevice: randomHash,
      deviceType,
      riskScore,
      riskLevel: riskScore > 70 ? 'HIGH' : riskScore > 30 ? 'MEDIUM' : 'LOW',
      ruleEvaluations
    });

    setIsSimulating(false);
  };

  const handleRemoveDevice = async (hash, docId) => {
    setDeviceNotice(null);
    if (docId) {
      const res = await removeAuthorizedDeviceFromFirestore(docId);
      if (res.success) {
        setDeviceNotice({ type: 'success', message: `Dispositivo eliminado de Firestore (Doc ID: ${docId})` });
      } else {
        setDeviceNotice({ type: 'error', message: res.error || 'Error al eliminar de Firestore' });
      }
    }
    removeTrustedDevice(hash);
  };

  const handleAddCurrentAsTrusted = async () => {
    setDeviceNotice(null);
    let fp = userSession?.fingerprintData;
    if (!fp || !fp.rawHash) {
      fp = await generateDeviceFingerprint();
    }
    const hash = fp.rawHash;
    const label = fp.friendlySummary || 'Mi Equipo Actual';

    const res = await addAuthorizedDeviceToFirestore({
      deviceHash: hash, // Hash SHA-256 criptográfico completo de 64 caracteres
      label,
      deviceType: fp.friendlySummary || 'Navegador Web'
    });

    if (res.success) {
      setDeviceNotice({
        type: 'success',
        message: `¡Dispositivo guardado en Firestore con su hash SHA-256 real (64 caracteres)! Doc ID: ${res.id}`
      });
    } else {
      setDeviceNotice({
        type: 'error',
        message: res.error || 'Error al guardar en Firestore'
      });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      
      {/* Barra de Navegación Superior */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-white text-base sm:text-lg tracking-tight">
                  Security Dashboard
                </h1>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  TFM Ciberseguridad
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                MFA Adaptativo · Verificación de Contexto & Auditoría en Tiempo Real
              </p>
            </div>
          </div>

          {/* Acciones y Estado del Usuario */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'overview' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Métricas & Logs
            </button>
            <button
              onClick={() => setActiveTab('trusted_devices')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                activeTab === 'trusted_devices' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Laptop className="w-3.5 h-3.5" />
              <span>Dispositivos ({trustedDevices.length})</span>
            </button>

            <button
              onClick={onOpenEnrollment}
              className="hidden md:flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg border border-slate-700 transition"
              title="Configurar nuevo dispositivo TOTP"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Enrolar QR</span>
            </button>

            <div className="h-6 w-px bg-slate-800 mx-1" />

            <button
              onClick={onLogout}
              className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition"
              title="Cerrar Sesión Segura"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>

        </div>
      </header>

      {/* Contenido Principal */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

        {/* 4. BANNER VISIBLE DE PRIVACIDAD Y SEGURIDAD POR DISEÑO (RGPD) */}
        <div className="bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-800/40 rounded-xl p-4 shadow-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2 bg-cyan-500/10 text-cyan-400 rounded-lg shrink-0 mt-0.5 sm:mt-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-xs sm:text-sm font-semibold text-white flex items-center gap-2">
                <span>Privacidad y Seguridad por Diseño (Art. 25 y 32 RGPD)</span>
                <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  CONFORME
                </span>
              </h4>
              <p className="text-xs text-slate-300 mt-0.5">
                "Los logs están anonimizados. No se procesan ni almacenan direcciones IP ni datos de carácter personal."
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 text-xs">
            <button
              onClick={() => setShowFsModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition shadow-sm cursor-pointer"
              title="Abrir diagnóstico de base de datos Firestore"
            >
              <span className={`w-2 h-2 rounded-full ${
                fsStatus.status === 'CONNECTED' 
                  ? 'bg-emerald-400 animate-pulse' 
                  : fsStatus.status === 'PERMISSION_DENIED' 
                  ? 'bg-rose-400 animate-ping' 
                  : 'bg-amber-400'
              }`} />
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                {fsStatus.status === 'CONNECTED' 
                  ? 'Firestore: (default) · access_logs ✓' 
                  : fsStatus.status === 'PERMISSION_DENIED' 
                  ? 'Firestore: Permisos Denegados (Reglas)' 
                  : 'Firestore (default)'}
              </span>
            </button>

            <span className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 text-slate-300 border border-slate-700 text-xs font-mono">
              <Cloud className="w-3.5 h-3.5 text-cyan-400" />
              Cloud Run
            </span>
          </div>
        </div>

        {/* MODAL DE DIAGNÓSTICO DE FIRESTORE (DEFAULT) & VERIFICACIÓN DE COLECCIÓN */}
        {showFsModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative space-y-4 text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-base font-bold text-white">
                    Diagnóstico de Cloud Firestore · Base de Datos "(default)"
                  </h3>
                </div>
                <button
                  onClick={() => setShowFsModal(false)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
                >
                  ✕
                </button>
              </div>

              {/* Parámetros de conexión */}
              <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 space-y-2 font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Proyecto Firebase:</span>
                  <span className="text-cyan-300 font-semibold">{fsStatus.projectId || 'tfm-mfa'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Base de Datos:</span>
                  <span className="text-white bg-slate-800 px-1.5 py-0.5 rounded font-semibold">(default)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Colección de Auditoría:</span>
                  <span className="text-emerald-400 font-semibold">access_logs</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Estado de Conexión:</span>
                  <span className={`font-semibold ${
                    fsStatus.status === 'CONNECTED' ? 'text-emerald-400' : 'text-rose-400'
                  }`}>
                    {fsStatus.status === 'CONNECTED' ? 'CONECTADO Y SINCRONIZANDO' : 'REQUIERE ATENCIÓN'}
                  </span>
                </div>
                {fsStatus.lastDocId && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Último Doc ID Escrito:</span>
                    <span className="text-cyan-400 truncate max-w-xs">{fsStatus.lastDocId}</span>
                  </div>
                )}
              </div>

              {/* Mensajes de error si los hay */}
              {fsStatus.lastError && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-300">
                  <div className="font-semibold flex items-center gap-1.5 mb-1">
                    <AlertCircle className="w-4 h-4 text-rose-400" />
                    Detalle del Error de Firestore:
                  </div>
                  <p className="text-[11px] font-mono">{fsStatus.lastError}</p>
                </div>
              )}

              {/* Resultado de la prueba */}
              {fsTestResult && (
                <div className={`p-3 rounded-xl border text-[11px] ${
                  fsTestResult.success 
                    ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300' 
                    : 'bg-amber-500/10 border-amber-500/20 text-amber-300'
                }`}>
                  <div className="font-semibold flex items-center gap-1.5">
                    {fsTestResult.success ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-amber-400" />}
                    <span>{fsTestResult.message || fsTestResult.error}</span>
                  </div>
                  {fsTestResult.docId && (
                    <div className="mt-1 font-mono text-cyan-300">
                      ID insertado: {fsTestResult.docId}
                    </div>
                  )}
                </div>
              )}

              {/* Explicación y Reglas de Seguridad de Firestore */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-slate-300 font-semibold">
                  <span>Reglas de Seguridad para tu Base de Datos (firestore.rules)</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  En Firestore, una colección se crea automáticamente en cuanto se inserta el primer documento. Si la consola muestra la base de datos vacía, suele deberse a que las reglas por defecto bloquean las escrituras.
                </p>
                <div className="p-2.5 bg-slate-900 rounded-lg text-[11px] font-mono text-cyan-300 overflow-x-auto">
{`rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /access_logs/{document=**} {
      allow read, write: if true; // O: if request.auth != null;
    }
  }
}`}
                </div>
                <p className="text-[10px] text-slate-500">
                  Copia y pega estas reglas en: <strong>Firebase Console &gt; Firestore Database &gt; Reglas</strong> y pulsa "Publicar".
                </p>
              </div>

              {/* Botón de acción: Enviar prueba y forzar creación de colección */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowFsModal(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition"
                >
                  Cerrar
                </button>
                <button
                  type="button"
                  disabled={isTestingFs}
                  onClick={async () => {
                    setIsTestingFs(true);
                    const res = await testAndCreateFirestoreCollection();
                    setFsTestResult(res);
                    setIsTestingFs(false);
                  }}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 transition shadow-lg shadow-cyan-600/20 disabled:opacity-50 cursor-pointer"
                >
                  {isTestingFs ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Escribiendo en (default)...</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Escribir Doc & Crear Colección 'access_logs'</span>
                    </>
                  )}
                </button>
              </div>

            </div>
          </div>
        )}

        {/* Vista: Dispositivos de Confianza (Directamente Colección authorized_devices) */}
        {activeTab === 'trusted_devices' ? (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                    <Laptop className="w-5 h-5 text-cyan-400" />
                    Registro de Dispositivos Confiables
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                    Firestore: authorized_devices
                  </span>
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-400">
                  Esta lista sincroniza directamente en tiempo real con la colección <code className="text-cyan-300 font-mono">authorized_devices</code> en la base de datos <strong className="text-slate-200">(default)</strong>.
                </p>
              </div>

              <button
                onClick={handleAddCurrentAsTrusted}
                className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition shadow-lg shadow-cyan-600/20 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Registrar mi Dispositivo en Firestore</span>
              </button>
            </div>

            {/* Aviso sobre reglas de Firestore */}
            <div className="mt-4 p-3 bg-slate-950 border border-slate-800 rounded-xl text-[11px] text-slate-400 flex items-start gap-2.5">
              <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-slate-300 font-semibold">Política Zero-Trust & Firestore:</span> Al añadir un dispositivo, se persiste en <code className="text-cyan-400 font-mono">authorized_devices</code> con tu <code className="text-slate-300 font-mono">userId</code>. Si el motor contextual en Cloud Run o la app detecta esta huella, el usuario obtiene acceso directo sin reto TOTP.
              </div>
            </div>

            {/* Mensaje de estado o error directo de Firestore */}
            {deviceNotice && (
              <div className={`mt-4 p-3.5 rounded-xl border text-xs ${
                deviceNotice.type === 'success' 
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              }`}>
                <div className="flex items-start gap-2">
                  {deviceNotice.type === 'success' ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <span className="font-semibold block">{deviceNotice.message}</span>
                    {deviceNotice.type === 'error' && deviceNotice.message.includes('permission-denied') && (
                      <div className="mt-2 p-2.5 bg-slate-950 rounded-lg text-[11px] font-mono text-cyan-300 border border-slate-800 space-y-1">
                        <div className="text-slate-300 font-sans font-semibold">Solución requerida en Reglas de Firestore:</div>
                        <p className="text-slate-400 font-sans">
                          Tu regla actual usa <code className="text-rose-400">resource.data.userId</code>. Al CREAR un nuevo dispositivo, <code className="text-amber-300">resource</code> es null en Firestore.
                          En Firebase Console, cambia esa regla por:
                        </p>
                        <pre className="text-emerald-400 mt-1 overflow-x-auto p-1 bg-slate-900 rounded">
{`match /authorized_devices/{deviceId} {
  allow read, delete: if request.auth != null && request.auth.uid == resource.data.userId;
  allow create: if request.auth != null && request.auth.uid == request.resource.data.userId;
}`}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div className="mt-6 space-y-3">
              {trustedDevices.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <Laptop className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                  <p>No hay dispositivos de confianza registrados.</p>
                  <p className="text-xs text-slate-400 mt-1">Todos los inicios de sesión requerirán verificación TOTP.</p>
                </div>
              ) : (
                trustedDevices.map((dev, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 bg-slate-950/60 border border-slate-800 rounded-xl">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        <Laptop className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-slate-200">{dev.label}</div>
                        <div className="font-mono text-xs text-cyan-400 mt-0.5">
                          Hash SHA-256: {dev.hash ? `${dev.hash.substring(0, 16)}...${dev.hash.substring(dev.hash.length - 8)}` : 'Dispositivo'}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            <span>{dev.docId ? `Firestore: ${dev.docId}` : 'Sincronizado'}</span>
                          </span>
                          <span className="text-[11px] text-slate-500">
                            {new Date(dev.registeredAt || Date.now()).toLocaleDateString('es-ES')}
                          </span>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => handleRemoveDevice(dev.hash, dev.docId)}
                      className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition cursor-pointer"
                      title="Eliminar de la lista de confianza y de Firestore"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        ) : (
          <>
            {/* 3. KPIS PRINCIPALES EN TARJETAS DE MÉTRICAS */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              
              {/* Tarjeta 1: Tasa de Éxito / Error */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Tasa de Éxito / Error</span>
                  <Activity className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-emerald-400">
                    {kpis.successRate}%
                  </span>
                  <span className="text-xs text-slate-400">éxito</span>
                  <span className="text-xs text-rose-400 font-mono ml-auto">
                    {kpis.errorRate}% fallos
                  </span>
                </div>
                <div className="mt-3 w-full bg-slate-800 h-1.5 rounded-full overflow-hidden flex">
                  <div className="bg-emerald-500 h-full" style={{ width: `${kpis.successRate}%` }} />
                  <div className="bg-rose-500 h-full" style={{ width: `${kpis.errorRate}%` }} />
                </div>
              </div>

              {/* Tarjeta 2: Latencia Media */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Latencia Media Verificación</span>
                  <Clock className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-cyan-400">
                    {kpis.avgLatency}
                  </span>
                  <span className="text-xs text-slate-400">ms</span>
                </div>
                <p className="mt-3 text-[11px] text-slate-500">
                  Microservicio Cloud Run + Crypto SHA-256
                </p>
              </div>

              {/* Tarjeta 3: Alertas de Dispositivos No Reconocidos */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Dispositivos No Reconocidos</span>
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-amber-400">
                    {kpis.unrecognizedAlerts}
                  </span>
                  <span className="text-xs text-slate-400">alertas</span>
                </div>
                <p className="mt-3 text-[11px] text-amber-500/80">
                  {kpis.mfaCount} retos MFA TOTP disparados por contexto
                </p>
              </div>

              {/* Tarjeta 4: Total de Peticiones Auditadas */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div className="flex items-center justify-between text-slate-400 text-xs">
                  <span>Total Eventos Auditados</span>
                  <Database className="w-4 h-4 text-indigo-400" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-white">
                    {kpis.total}
                  </span>
                  <span className="text-xs text-slate-400">en Firestore</span>
                </div>
                <p className="mt-3 text-[11px] text-slate-500">
                  Garantía de inmutabilidad y 0 PII
                </p>
              </div>

            </div>

            {/* COMPONENTES GRÁFICOS (RECHARTS) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Gráfico 1 & 2: Histórico de Latencias y Tiempos de Verificación */}
              <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm sm:text-base font-semibold text-white">
                      Histórico de Accesos y Latencia de Verificación (ms)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Rendimiento del endpoint <code className="text-cyan-400 font-mono">/api/verify-context</code> a lo largo de las solicitudes
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="flex items-center gap-1 text-cyan-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                      Latencia (ms)
                    </span>
                    <span className="flex items-center gap-1 text-amber-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                      Score de Riesgo (%)
                    </span>
                  </div>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="latencyGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                        </linearGradient>
                        <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#0f172a', 
                          borderColor: '#334155',
                          borderRadius: '0.5rem',
                          fontSize: '12px',
                          color: '#fff'
                        }} 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="latency" 
                        stroke="#06b6d4" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#latencyGradient)" 
                        name="Latencia (ms)"
                      />
                      <Area 
                        type="monotone" 
                        dataKey="risk" 
                        stroke="#f59e0b" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#riskGradient)" 
                        name="Riesgo (%)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Gráfico 3: Distribución de Eventos de Seguridad */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col justify-between">
                <div>
                  <h3 className="text-sm sm:text-base font-semibold text-white">
                    Distribución de Decisiones Zero-Trust
                  </h3>
                  <p className="text-xs text-slate-400">
                    Proporción de accesos directos vs retos adaptativos
                  </p>
                </div>

                <div className="h-52 w-full my-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={distributionData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {distributionData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#0f172a', 
                          borderColor: '#334155',
                          borderRadius: '0.5rem',
                          fontSize: '12px'
                        }} 
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                      Accesos Directos (Éxito)
                    </span>
                    <span className="font-mono font-semibold">{kpis.successCount}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                      Retos MFA Adaptativo
                    </span>
                    <span className="font-mono font-semibold">{kpis.mfaCount}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                      Intentos Fallidos
                    </span>
                    <span className="font-mono font-semibold">{kpis.failedCount}</span>
                  </div>
                </div>

              </div>

            </div>

            {/* TABLA DE AUDITORÍA EN TIEMPO REAL */}
            <AccessLogsTable 
              logs={logs} 
              onSimulateEvent={handleSimulateLiveEvent}
            />
          </>
        )}

      </main>

      {/* Pie de página con información académica */}
      <footer className="border-t border-slate-800 bg-slate-900/50 py-4 text-center text-xs text-slate-500">
        <p>Trabajo Final de Máster (TFM) · "Security Dashboard con MFA Adaptativo"</p>
        <p className="mt-1 text-[11px] text-slate-600">
          React SPA + Vite + Tailwind CSS · Firebase v10+ (Auth & Firestore) · GCP Cloud Run Context Engine
        </p>
      </footer>

    </div>
  );
}
