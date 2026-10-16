/**
 * Componente: Dashboard.jsx
 * Panel Principal de Monitorización de Seguridad y Auditoría Zero-Trust
 * 
 * Estética unificada en tono azul blanco y tarjetas blancas con sombras suaves.
 * - Registro de accesos en tiempo real con Firestore
 * - Sincronización bidireccional de la colección 'authorized_devices'
 * - Métricas de latencia de Cloud Run y toma de decisiones contextuales
 */

import React, { useState, useEffect, useMemo } from 'react';
import { 
  Activity, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  Database, 
  Laptop, 
  LogOut, 
  Plus, 
  Trash2, 
  RefreshCw, 
  CheckCircle, 
  AlertCircle,
  Cloud
} from 'lucide-react';

import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart, 
  Pie, 
  Cell
} from 'recharts';

import AccessLogsTable from './AccessLogsTable';
import { 
  subscribeToAccessLogs, 
  recordAccessLog, 
  isFirebaseConfigured, 
  CLOUD_RUN_API_URL,
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
  sky: '#0284c7',     // sky-600
  slate: '#64748b'
};

export default function Dashboard({ 
  userSession, 
  onLogout 
}) {
  const [logs, setLogs] = useState([]);
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'trusted_devices'
  const [deviceNotice, setDeviceNotice] = useState(null); // { type: 'success' | 'error', message: string }

  // Suscripción en tiempo real a los logs de auditoría de Firestore
  useEffect(() => {
    const unsubscribeLogs = subscribeToAccessLogs((liveLogs) => {
      if (liveLogs && liveLogs.length > 0) {
        setLogs(liveLogs);
      }
    });

    // Suscripción en tiempo real a la colección 'authorized_devices' de Firestore
    const unsubscribeDevices = subscribeToAuthorizedDevices((liveDevices) => {
      if (liveDevices) {
        const local = getTrustedDevices();
        const combined = [...liveDevices];
        local.forEach(l => {
          if (!combined.some(c => c.hash === l.hash)) {
            combined.push(l);
          }
        });
        setTrustedDevices(combined);
      }
    });

    return () => {
      if (unsubscribeLogs) unsubscribeLogs();
      if (unsubscribeDevices) unsubscribeDevices();
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

    // Alertas: eventos con dispositivos no reconocidos que dispararon reto MFA
    const unrecognizedAlerts = logs.filter(l => l.status === 'MFA_REQUIRED').length;

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
      { name: 'Accesos Directos', value: kpis.successCount, color: COLORS.success },
      { name: 'Retos MFA Adaptativo', value: kpis.mfaCount, color: COLORS.mfa },
      { name: 'Intentos Fallidos', value: kpis.failedCount, color: COLORS.failed }
    ].filter(item => item.value > 0);
  }, [kpis]);

  // Generador de eventos de simulación en vivo
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

    let ruleEvaluations = [];

    if (selectedType === 'SUCCESS') {
      ruleEvaluations = ['Dispositivo conocido verificado en authorized_devices', 'Acceso directo autorizado'];
    } else if (selectedType === 'MFA_REQUIRED') {
      ruleEvaluations = ['Dispositivo nuevo no catalogado', 'Reto adaptativo TOTP disparado'];
    } else {
      ruleEvaluations = ['Credencial errónea de primer factor', 'Intento bloqueado preventivamente'];
    }

    await recordAccessLog({
      status: selectedType,
      latencyMs: randomLatency,
      anonymizedDevice: randomHash,
      deviceType,
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
      deviceHash: hash,
      label,
      deviceType: fp.friendlySummary || 'Navegador Web'
    });

    if (res.success) {
      setDeviceNotice({
        type: 'success',
        message: `¡Dispositivo guardado en Firestore con su hash SHA-256 real! Doc ID: ${res.id}`
      });
    } else {
      setDeviceNotice({
        type: 'error',
        message: res.error || 'Error al guardar en Firestore'
      });
    }
  };

  return (
    <div className="min-h-screen bg-transparent text-slate-800 flex flex-col font-sans">
      
      {/* Barra de Navegación Superior */}
      <header className="border-b border-sky-200/80 bg-white/85 backdrop-blur-md sticky top-0 z-40 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-sky-50 border border-sky-200 text-sky-600 shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-bold text-slate-900 text-base sm:text-lg tracking-tight">
                TFM - Implementación de un Sistema MFA
              </h1>
              <p className="text-xs text-slate-500 hidden sm:block">
                MFA Adaptativo · Verificación de Contexto & Auditoría en Tiempo Real
              </p>
            </div>
          </div>

          {/* Acciones, Pestañas y Estado */}
          <div className="flex items-center gap-2 sm:gap-3">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'overview' 
                  ? 'bg-sky-600 text-white shadow-sm' 
                  : 'text-slate-600 hover:text-slate-900 bg-slate-100/80'
              }`}
            >
              Métricas & Logs
            </button>
            <button
              onClick={() => setActiveTab('trusted_devices')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'trusted_devices' 
                  ? 'bg-sky-600 text-white shadow-sm' 
                  : 'text-slate-600 hover:text-slate-900 bg-slate-100/80'
              }`}
            >
              <Laptop className="w-3.5 h-3.5" />
              <span>Dispositivos ({trustedDevices.length})</span>
            </button>

            <div className="h-6 w-px bg-slate-200 mx-1" />

            <button
              onClick={onLogout}
              className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition cursor-pointer"
              title="Cerrar Sesión Segura"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>

        </div>
      </header>

      {/* Contenido Principal */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

        {/* Vista: Dispositivos de Confianza (Directamente Colección authorized_devices) */}
        {activeTab === 'trusted_devices' ? (
          <div className="bg-white/95 border border-sky-100 rounded-2xl p-6 shadow-xl shadow-sky-950/5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                    <Laptop className="w-5 h-5 text-sky-600" />
                    Registro de Dispositivos Confiables
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-sky-50 text-sky-700 border border-sky-200 font-semibold">
                    authorized_devices
                  </span>
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-slate-500">
                  Esta lista sincroniza en tiempo real con la colección de dispositivos autorizados <code className="text-sky-700 font-mono">authorized_devices</code>.
                </p>
              </div>

              <button
                onClick={handleAddCurrentAsTrusted}
                className="px-4 py-2.5 bg-gradient-to-r from-sky-600 via-blue-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition shadow-md shadow-sky-600/20 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Registrar mi Dispositivo</span>
              </button>
            </div>

            {/* Aviso sobre reglas de Firestore */}
            <div className="mt-4 p-3 bg-sky-50/70 border border-sky-100 rounded-xl text-[11px] text-slate-600 flex items-start gap-2.5">
              <Shield className="w-4 h-4 text-sky-600 shrink-0 mt-0.5" />
              <div>
                <span className="text-slate-800 font-semibold">Política Zero-Trust & Firestore:</span> Al añadir un dispositivo, se persiste en <code className="text-sky-700 font-mono">authorized_devices</code>. Si el sistema detecta esta huella criptográfica SHA-256 en inicios de sesión posteriores, el usuario obtiene acceso directo sin reto TOTP.
              </div>
            </div>

            {/* Mensaje de estado o error directo de Firestore */}
            {deviceNotice && (
              <div className={`mt-4 p-3.5 rounded-xl border text-xs ${
                deviceNotice.type === 'success' 
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800' 
                  : 'bg-rose-50 border-rose-200 text-rose-800'
              }`}>
                <div className="flex items-start gap-2">
                  {deviceNotice.type === 'success' ? (
                    <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <span className="font-semibold block">{deviceNotice.message}</span>
                  </div>
                </div>
              </div>
            )}

            <div className="mt-6 space-y-3">
              {trustedDevices.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <Laptop className="w-10 h-10 mx-auto mb-2 text-slate-300" />
                  <p className="font-medium text-slate-700">No hay dispositivos de confianza registrados.</p>
                  <p className="text-xs text-slate-400 mt-1">Todos los inicios de sesión requerirán verificación TOTP adaptativa.</p>
                </div>
              ) : (
                trustedDevices.map((dev, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 bg-slate-50/70 border border-slate-200 rounded-xl hover:bg-slate-50 transition">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-lg bg-sky-50 text-sky-600 border border-sky-200 shadow-sm">
                        <Laptop className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-slate-900">{dev.label}</div>
                        <div className="font-mono text-xs text-sky-800 mt-0.5">
                          Hash SHA-256: {dev.hash ? `${dev.hash.substring(0, 16)}...${dev.hash.substring(dev.hash.length - 8)}` : 'Dispositivo'}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1 font-semibold">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
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
                      className="p-2 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition cursor-pointer"
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
              <div className="bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5 relative overflow-hidden">
                <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                  <span>Tasa de Éxito / Error</span>
                  <Activity className="w-4 h-4 text-sky-600" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-emerald-600">
                    {kpis.successRate}%
                  </span>
                  <span className="text-xs text-slate-500">éxito</span>
                  <span className="text-xs text-rose-600 font-mono ml-auto font-medium">
                    {kpis.errorRate}% fallos
                  </span>
                </div>
                <div className="mt-3 w-full bg-slate-100 h-1.5 rounded-full overflow-hidden flex">
                  <div className="bg-emerald-500 h-full" style={{ width: `${kpis.successRate}%` }} />
                  <div className="bg-rose-500 h-full" style={{ width: `${kpis.errorRate}%` }} />
                </div>
              </div>

              {/* Tarjeta 2: Latencia Media */}
              <div className="bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5">
                <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                  <span>Latencia Media Verificación</span>
                  <Clock className="w-4 h-4 text-sky-600" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-sky-700">
                    {kpis.avgLatency}
                  </span>
                  <span className="text-xs text-slate-500">ms</span>
                </div>
                <p className="mt-3 text-[11px] text-slate-400">
                  Microservicio Cloud Run + Crypto SHA-256
                </p>
              </div>

              {/* Tarjeta 3: Alertas de Dispositivos No Reconocidos */}
              <div className="bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5">
                <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                  <span>Dispositivos No Reconocidos</span>
                  <ShieldAlert className="w-4 h-4 text-amber-600" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-amber-600">
                    {kpis.unrecognizedAlerts}
                  </span>
                  <span className="text-xs text-slate-500">alertas</span>
                </div>
                <p className="mt-3 text-[11px] text-amber-700/90 font-medium">
                  {kpis.mfaCount} retos MFA TOTP disparados por contexto
                </p>
              </div>

              {/* Tarjeta 4: Total de Peticiones Auditadas */}
              <div className="bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5">
                <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
                  <span>Total Eventos Auditados</span>
                  <Database className="w-4 h-4 text-indigo-600" />
                </div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span className="text-2xl sm:text-3xl font-bold font-mono text-slate-900">
                    {kpis.total}
                  </span>
                  <span className="text-xs text-slate-500">en Firestore</span>
                </div>
                <p className="mt-3 text-[11px] text-slate-400">
                  Garantía de inmutabilidad y 0 PII
                </p>
              </div>

            </div>

            {/* COMPONENTES GRÁFICOS (RECHARTS) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Gráfico 1: Histórico de Latencias */}
              <div className="lg:col-span-2 bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm sm:text-base font-bold text-slate-900">
                      Histórico de Accesos y Latencia de Verificación (ms)
                    </h3>
                    <p className="text-xs text-slate-500">
                      Rendimiento del endpoint <code className="text-sky-700 font-mono font-medium">/api/verify-context</code> a lo largo de las solicitudes
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="flex items-center gap-1 text-sky-700 font-medium">
                      <span className="w-2.5 h-2.5 rounded-full bg-sky-600" />
                      Latencia (ms)
                    </span>
                  </div>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="latencyGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#0284c7" stopOpacity={0.35}/>
                          <stop offset="95%" stopColor="#0284c7" stopOpacity={0.0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#ffffff', 
                          borderColor: '#cbd5e1',
                          borderRadius: '0.75rem',
                          fontSize: '12px',
                          color: '#0f172a',
                          boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
                        }} 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="latency" 
                        stroke="#0284c7" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#latencyGradient)" 
                        name="Latencia (ms)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Gráfico 2: Distribución de Eventos de Seguridad */}
              <div className="bg-white/95 border border-sky-100 rounded-2xl p-5 shadow-sm shadow-sky-950/5 flex flex-col justify-between">
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-slate-900">
                    Distribución de Decisiones Zero-Trust
                  </h3>
                  <p className="text-xs text-slate-500">
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
                          backgroundColor: '#ffffff', 
                          borderColor: '#cbd5e1',
                          borderRadius: '0.75rem',
                          fontSize: '12px',
                          color: '#0f172a'
                        }} 
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between text-slate-700">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                      Accesos Directos (Éxito)
                    </span>
                    <span className="font-mono font-semibold text-slate-900">{kpis.successCount}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-700">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                      Retos MFA Adaptativo
                    </span>
                    <span className="font-mono font-semibold text-slate-900">{kpis.mfaCount}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-700">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                      Intentos Fallidos
                    </span>
                    <span className="font-mono font-semibold text-slate-900">{kpis.failedCount}</span>
                  </div>
                </div>

              </div>

            </div>

            {/* TABLA DE AUDITORÍA EN TIEMPO REAL CON PAGINACIÓN */}
            <AccessLogsTable 
              logs={logs} 
              onSimulateEvent={handleSimulateLiveEvent}
            />
          </>
        )}

      </main>

      {/* Pie de página */}
      <footer className="border-t border-slate-200/80 bg-white/60 py-4 text-center text-xs text-slate-500">
        <p>Security Dashboard con MFA Adaptativo · Evaluación de Contexto en Tiempo Real</p>
        <p className="mt-0.5 text-[11px] text-slate-400">
          React SPA + Vite + Tailwind CSS · Firebase Auth & Cloud Firestore
        </p>
      </footer>

    </div>
  );
}
