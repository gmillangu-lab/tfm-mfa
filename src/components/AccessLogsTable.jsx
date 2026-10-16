/**
 * Componente: AccessLogsTable.jsx
 * Tabla de Auditoría de Accesos en Tiempo Real con Paginación
 * 
 * Muestra eventos de autenticación anonimizados cumpliendo RGPD:
 * - Fecha / Hora
 * - Estado del Evento (SUCCESS, MFA_REQUIRED, FAILED)
 * - Latencia (ms)
 * - Dispositivo Anonimizado (Hash SHA-256 truncado)
 * - Paginación reactiva para evitar crecimiento indefinido
 */

import React, { useState, useMemo } from 'react';
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
  ChevronUp,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

export default function AccessLogsTable({ logs = [], onRefresh, onSimulateEvent }) {
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Filtrado reactivo de logs
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesStatus = filterStatus === 'ALL' || log.status === filterStatus;
      const matchesSearch = !searchQuery || 
        (log.anonymizedDevice && log.anonymizedDevice.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (log.deviceType && log.deviceType.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesStatus && matchesSearch;
    });
  }, [logs, filterStatus, searchQuery]);

  // Cálculo de paginación
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize));
  
  // Asegurar que la página actual sea válida
  const activePage = Math.min(currentPage, totalPages);

  const paginatedLogs = useMemo(() => {
    const startIndex = (activePage - 1) * pageSize;
    return filteredLogs.slice(startIndex, startIndex + pageSize);
  }, [filteredLogs, activePage, pageSize]);

  const handleFilterChange = (status) => {
    setFilterStatus(status);
    setCurrentPage(1);
  };

  const handleSearchChange = (query) => {
    setSearchQuery(query);
    setCurrentPage(1);
  };

  const handlePageSizeChange = (newSize) => {
    setPageSize(Number(newSize));
    setCurrentPage(1);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            SUCCESS
          </span>
        );
      case 'MFA_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-600" />
            MFA_REQUIRED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
            <ShieldX className="w-3.5 h-3.5 text-rose-600" />
            FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
            {status}
          </span>
        );
    }
  };

  const getLatencyColor = (ms) => {
    if (ms < 150) return 'text-emerald-700 font-mono font-medium';
    if (ms < 300) return 'text-amber-700 font-mono font-medium';
    return 'text-rose-700 font-mono font-medium';
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
    <div className="bg-white/95 border border-sky-100 rounded-2xl overflow-hidden shadow-xl shadow-sky-950/5 backdrop-blur-md">
      {/* Cabecera y Controles de la Tabla */}
      <div className="p-4 sm:p-5 border-b border-slate-100 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              Registro de Auditoría de Accesos
            </h3>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-sky-50 text-sky-700 border border-sky-200">
              {logs.length} eventos
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Eventos de seguridad y acceso sincronizados en tiempo real.
          </p>
        </div>

        {/* Buscador, Filtros y Paginación rápida */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Búsqueda por huella o dispositivo */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Buscar por hash o equipo..."
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-50/80 border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-sky-500 focus:ring-1 focus:ring-sky-500 w-44 sm:w-56"
            />
          </div>

          {/* Filtros de Estado */}
          <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => handleFilterChange('ALL')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'ALL' ? 'bg-sky-600 text-white font-medium shadow-sm' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Todos ({logs.length})
            </button>
            <button
              onClick={() => handleFilterChange('SUCCESS')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'SUCCESS' ? 'bg-emerald-600 text-white font-medium shadow-sm' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Éxito
            </button>
            <button
              onClick={() => handleFilterChange('MFA_REQUIRED')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'MFA_REQUIRED' ? 'bg-amber-600 text-white font-medium shadow-sm' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              MFA
            </button>
            <button
              onClick={() => handleFilterChange('FAILED')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filterStatus === 'FAILED' ? 'bg-rose-600 text-white font-medium shadow-sm' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Fallo
            </button>
          </div>

          {onSimulateEvent && (
            <button
              onClick={onSimulateEvent}
              className="px-3 py-1.5 text-xs font-medium bg-sky-50 hover:bg-sky-100 text-sky-800 rounded-lg border border-sky-200 transition flex items-center gap-1.5 shadow-sm cursor-pointer"
              title="Disparar un evento de auditoría de prueba en tiempo real"
            >
              <RefreshCw className="w-3.5 h-3.5 text-sky-600" />
              <span>Simular Acceso</span>
            </button>
          )}
        </div>
      </div>

      {/* Tabla con Responsive Scroll */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead className="bg-slate-50/80 text-slate-600 border-b border-slate-200 uppercase text-[11px] tracking-wider font-semibold">
            <tr>
              <th className="py-3 px-4">Fecha / Hora</th>
              <th className="py-3 px-4">Estado del Evento</th>
              <th className="py-3 px-4">Latencia</th>
              <th className="py-3 px-4">Dispositivo Anonimizado (RGPD)</th>
              <th className="py-3 px-4 text-right">Detalles</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {paginatedLogs.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-12 text-slate-500">
                  <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                  No se encontraron eventos de acceso con los filtros seleccionados.
                </td>
              </tr>
            ) : (
              paginatedLogs.map((log) => {
                const isExpanded = expandedLogId === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <tr className="hover:bg-sky-50/50 transition-colors">
                      {/* Fecha / Hora */}
                      <td className="py-3.5 px-4 font-mono text-slate-700 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-slate-400" />
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
                          <Laptop className="w-4 h-4 text-sky-600 shrink-0" />
                          <div>
                            <div className="font-mono text-xs text-sky-900 font-semibold">
                              {log.anonymizedDevice}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {log.deviceType || 'Navegador Web Estándar'}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Botón de despliegue */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                          className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition cursor-pointer"
                          title="Inspeccionar evaluación contextual"
                        >
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-sky-600" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </button>
                      </td>
                    </tr>

                    {/* Fila desplegable con evaluación contextual */}
                    {isExpanded && (
                      <tr className="bg-sky-50/40">
                        <td colSpan={5} className="p-4 border-t border-slate-200">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                            <div className="bg-white p-3.5 rounded-xl border border-sky-100 shadow-sm">
                              <h4 className="font-semibold text-slate-800 mb-2 flex items-center gap-1.5">
                                <Info className="w-3.5 h-3.5 text-sky-600" />
                                Reglas de Contexto Evaluadas por Cloud Run
                              </h4>
                              {log.ruleEvaluations && log.ruleEvaluations.length > 0 ? (
                                <ul className="space-y-1 list-disc list-inside text-slate-600">
                                  {log.ruleEvaluations.map((rule, idx) => (
                                    <li key={idx}>{rule}</li>
                                  ))}
                                </ul>
                              ) : (
                                <p className="text-slate-500 italic">Evaluación estándar de huella completada.</p>
                              )}
                            </div>

                            <div className="bg-white p-3.5 rounded-xl border border-sky-100 shadow-sm">
                              <h4 className="font-semibold text-slate-800 mb-2 flex items-center gap-1.5">
                                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                                Garantías RGPD & Privacidad por Diseño
                              </h4>
                              <p className="text-slate-600 leading-relaxed">
                                Conforme al Art. 25 y 32 del RGPD: Identificador calculado mediante hash unidireccional SHA-256. La dirección IP y datos de carácter personal (PII) son eliminados previo al registro inmutable.
                              </p>
                              <div className="mt-2 text-[11px] text-emerald-700 font-mono font-medium">
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

      {/* Pie de tabla con Controles de Paginación */}
      <div className="p-3.5 bg-slate-50/80 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-600">
        
        {/* Información de Registros */}
        <div className="flex items-center gap-3">
          <span>
            Mostrando {filteredLogs.length === 0 ? 0 : (activePage - 1) * pageSize + 1} - {Math.min(activePage * pageSize, filteredLogs.length)} de {filteredLogs.length} eventos
          </span>
          <div className="flex items-center gap-1.5 text-slate-500">
            <span>| Filas:</span>
            <select
              value={pageSize}
              onChange={(e) => handlePageSizeChange(e.target.value)}
              className="bg-white border border-slate-200 rounded px-1.5 py-0.5 text-slate-700 text-xs focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>

        {/* Botones de Navegación de Páginas */}
        <div className="flex items-center gap-2">
          <span className="text-slate-500 font-medium mr-1">
            Página {activePage} de {totalPages}
          </span>

          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={activePage <= 1}
            className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition cursor-pointer flex items-center gap-1 shadow-sm"
            title="Página anterior"
          >
            <ChevronLeft className="w-4 h-4" />
            <span className="hidden sm:inline text-xs">Anterior</span>
          </button>

          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={activePage >= totalPages}
            className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition cursor-pointer flex items-center gap-1 shadow-sm"
            title="Página siguiente"
          >
            <span className="hidden sm:inline text-xs">Siguiente</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

      </div>
    </div>
  );
}
