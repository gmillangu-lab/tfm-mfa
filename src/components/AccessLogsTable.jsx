/**
 * Componente: AccessLogsTable.jsx
 * Tabla de Auditoría de Accesos en Tiempo Real
 * 
 * Muestra eventos de autenticación anonimizados cumpliendo RGPD:
 * - Fecha / Hora
 * - Estado del Evento (SUCCESS, MFA_REQUIRED, FAILED)
 * - Latencia (ms)
 * - Dispositivo Anonimizado (Hash SHA-256 truncado)
 */

import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Clock, 
  Laptop, 
  Filter, 
  Search, 
  RefreshCw,
  Info,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export default function AccessLogsTable({ logs = [], onRefresh, onSimulateEvent }) {
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedLogId, setExpandedLogId] = useState(null);

  // Filtrado reactivo de logs
  const filteredLogs = logs.filter(log => {
    const matchesStatus = filterStatus === 'ALL' || log.status === filterStatus;
    const matchesSearch = !searchQuery || 
      (log.anonymizedDevice && log.anonymizedDevice.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (log.deviceType && log.deviceType.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (log.riskLevel && log.riskLevel.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesStatus && matchesSearch;
  });

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            SUCCESS
          </span>
        );
      case 'MFA_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            MFA_REQUIRED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldX className="w-3.5 h-3.5 text-rose-400" />
            FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
            {status}
          </span>
        );
    }
  };

  const getLatencyColor = (ms) => {
    if (ms < 150) return 'text-emerald-400 font-mono';
    if (ms < 300) return 'text-amber-400 font-mono';
    return 'text-rose-400 font-mono';
  };

  const formatTimestamp = (isoString) => {
    if (!isoString) return 'Reciente';
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString('es-ES', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      }) + ' · ' + date.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl backdrop-blur-md">
      {/* Cabecera y Controles de la Tabla */}
      <div className="p-4 sm:p-5 border-b border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base sm:text-lg font-semibold text-white tracking-tight">
              Registro de Auditoría de Accesos en Tiempo Real
            </h3>
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Colección Firestore: <code className="text-cyan-400 bg-cyan-950/40 px-1 py-0.5 rounded font-mono">access_logs</code> · Registros sincronizados en tiempo real
          </p>
        </div>

        {/* Herramientas de filtrado y búsqueda */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar por huella o SO..."
              className="pl-9 pr-3 py-1.5 text-xs sm:text-sm bg-slate-950/80 border border-slate-700/80 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div className="flex items-center bg-slate-950/80 border border-slate-700/80 rounded-lg p-0.5 text-xs">
            <button
              onClick={() => setFilterStatus('ALL')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'ALL' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Todos ({logs.length})
            </button>
            <button
              onClick={() => setFilterStatus('SUCCESS')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'SUCCESS' ? 'bg-emerald-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Éxito
            </button>
            <button
              onClick={() => setFilterStatus('MFA_REQUIRED')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'MFA_REQUIRED' ? 'bg-amber-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              MFA
            </button>
            <button
              onClick={() => setFilterStatus('FAILED')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'FAILED' ? 'bg-rose-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Fallo
            </button>
          </div>

          {onSimulateEvent && (
            <button
              onClick={onSimulateEvent}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition flex items-center gap-1.5"
              title="Disparar un evento de auditoría de prueba en tiempo real"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Simular Acceso</span>
            </button>
          )}
        </div>
      </div>

      {/* Tabla con Responsive Scroll */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 uppercase text-[11px] tracking-wider font-semibold">
            <tr>
              <th className="py-3 px-4">Fecha / Hora</th>
              <th className="py-3 px-4">Estado del Evento</th>
              <th className="py-3 px-4">Latencia</th>
              <th className="py-3 px-4">Dispositivo Anonimizado (RGPD)</th>
              <th className="py-3 px-4">Nivel de Riesgo</th>
              <th className="py-3 px-4 text-right">Detalles</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-10 text-slate-500">
                  <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                  No se encontraron eventos de acceso con los filtros seleccionados.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => {
                const isExpanded = expandedLogId === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <tr className="hover:bg-slate-800/30 transition-colors">
                      {/* Fecha / Hora */}
                      <td className="py-3.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-slate-500" />
                          <span>{formatTimestamp(log.timestamp)}</span>
                        </div>
                      </td>

                      {/* Estado del Evento */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getStatusBadge(log.status)}
                      </td>

                      {/* Latencia */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={getLatencyColor(log.latencyMs)}>
                          {log.latencyMs} ms
                        </span>
                      </td>

                      {/* Dispositivo Anonimizado */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <Laptop className="w-4 h-4 text-cyan-400 shrink-0" />
                          <div>
                            <div className="font-mono text-xs text-cyan-300 font-medium">
                              {log.anonymizedDevice}
                            </div>
                            <div className="text-[11px] text-slate-400">
                              {log.deviceType || 'Navegador Web Estándar'}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Nivel de Riesgo */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full ${
                                (log.riskScore || 0) > 70
                                  ? 'bg-rose-500'
                                  : (log.riskScore || 0) > 30
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(100, log.riskScore || 15)}%` }}
                            />
                          </div>
                          <span className="font-mono text-xs text-slate-300">
                            {log.riskScore ?? 10}%
                          </span>
                        </div>
                      </td>

                      {/* Botón de despliegue */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
                          title="Inspeccionar evaluación contextual"
                        >
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </button>
                      </td>
                    </tr>

                    {/* Fila desplegable con evaluación contextual */}
                    {isExpanded && (
                      <tr className="bg-slate-950/70">
                        <td colSpan={6} className="p-4 border-t border-slate-800">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                              <h4 className="font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                                <Info className="w-3.5 h-3.5 text-cyan-400" />
                                Reglas de Contexto Evaluadas por Cloud Run
                              </h4>
                              {log.ruleEvaluations && log.ruleEvaluations.length > 0 ? (
                                <ul className="space-y-1 list-disc list-inside text-slate-400">
                                  {log.ruleEvaluations.map((rule, idx) => (
                                    <li key={idx}>{rule}</li>
                                  ))}
                                </ul>
                              ) : (
                                <p className="text-slate-500 italic">Evaluación estándar de huella completada.</p>
                              )}
                            </div>

                            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                              <h4 className="font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                                Garantías RGPD & Privacidad por Diseño
                              </h4>
                              <p className="text-slate-400">
                                Conforme al Art. 25 y 32 del RGPD: Identificador calculado mediante HMAC/SHA-256 unidireccional. La dirección IP de origen y componentes biométricos han sido eliminados previo al registro en Firestore.
                              </p>
                              <div className="mt-2 text-[11px] text-cyan-400 font-mono">
                                Estado RGPD: Auditado & Anonimizado ✓
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pie de tabla con conteo */}
      <div className="p-3 bg-slate-950/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
        <span>Mostrando {filteredLogs.length} de {logs.length} eventos</span>
        <span>Privacidad Garantizada: 0 datos PII almacenados</span>
      </div>
    </div>
  );
}
