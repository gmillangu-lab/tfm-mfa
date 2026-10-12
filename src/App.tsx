/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import LoginForm from './components/LoginForm';
import TotpVerification from './components/TotpVerification';
import TotpEnrollment from './components/TotpEnrollment';
import Dashboard from './components/Dashboard';
import { Shield, CheckCircle2, Lock, KeyRound, AlertTriangle } from 'lucide-react';
import { auth, isFirebaseConfigured } from './firebaseConfig';
import { signOut, onAuthStateChanged } from 'firebase/auth';

export default function App() {
  // Vistas controladas: 'login' | 'mfa_challenge' | 'enrollment' | 'dashboard'
  const [currentView, setCurrentView] = useState<'login' | 'mfa_challenge' | 'enrollment' | 'dashboard'>('login');
  
  // Sesión autenticada y verificada
  const [userSession, setUserSession] = useState<any>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  // Escuchar cambios de autenticación en Firebase
  useEffect(() => {
    if (auth && isFirebaseConfigured()) {
      const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
        if (!firebaseUser && currentView === 'dashboard') {
          setUserSession(null);
          setCurrentView('login');
        }
      });
      return () => unsubscribe();
    }
  }, [currentView]);

  // Si no hay sesión válida, BLOQUEO ESTRICTO: no permitir acceder al Dashboard
  const isAuthorizedForDashboard = Boolean(
    userSession && (userSession.mfaVerified || userSession.mfaBypassedByTrust)
  );

  // Manejador cuando se detecta riesgo contextual y Cloud Run exige MFA TOTP
  const handleRequireMfa = (sessionData: any) => {
    setUserSession(sessionData);
    setCurrentView('mfa_challenge');
    showNotification('Reto MFA adaptativo disparado: Por favor verifica el código TOTP');
  };

  // Manejador de login exitoso directo (dispositivo habitual confiable)
  const handleLoginSuccess = (sessionData: any) => {
    setUserSession(sessionData);
    setCurrentView('dashboard');
    showNotification('¡Acceso concedido! Dispositivo de confianza verificado');
  };

  // Manejador cuando el usuario se acaba de registrar y pasa al enrolamiento del QR
  const handleAccountCreatedAndEnrolling = (newAccountData: any) => {
    setUserSession(newAccountData);
    setCurrentView('enrollment');
    showNotification('Cuenta creada en Firebase. Configura tu Google Authenticator');
  };

  // Manejador cuando se verifica satisfactoriamente el 2º factor TOTP
  const handleMfaSuccess = (verifiedSession: any) => {
    setUserSession({
      ...verifiedSession,
      mfaVerified: true
    });
    setCurrentView('dashboard');
    showNotification('Segundo factor verificado con éxito. Bienvenido al Dashboard');
  };

  // Manejador de enrolamiento completado
  const handleEnrollmentComplete = (enrollmentData: any) => {
    showNotification('¡Autenticador TOTP vinculado con éxito!');
    if (userSession) {
      // Tras enrolarse, se le pide el código de verificación para completar la entrada
      setCurrentView('mfa_challenge');
    } else {
      setCurrentView('login');
    }
  };

  // Cierre de sesión seguro
  const handleLogout = async () => {
    try {
      if (auth && isFirebaseConfigured()) {
        await signOut(auth);
      }
    } catch (e) {
      console.warn('Error al cerrar sesión en Firebase Auth:', e);
    }
    setUserSession(null);
    setCurrentView('login');
    showNotification('Sesión cerrada correctamente');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      
      {/* Toast de notificación flotante */}
      {notification && (
        <div className="fixed top-4 right-4 z-50 animate-bounce">
          <div className="bg-slate-900 border border-cyan-500/40 text-cyan-300 px-4 py-2.5 rounded-xl shadow-2xl text-xs font-semibold flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>{notification}</span>
          </div>
        </div>
      )}

      {/* RENDERIZADO DEL DASHBOARD: ÚNICAMENTE SI ESTÁ AUTENTICADO Y VERIFICADO */}
      {currentView === 'dashboard' && isAuthorizedForDashboard ? (
        <Dashboard 
          userSession={userSession}
          onLogout={handleLogout}
          onOpenEnrollment={() => setCurrentView('enrollment')}
        />
      ) : (
        /* Vistas de Autenticación Previa (Login, Registro, Reto MFA, Enrolamiento) */
        <div className="flex-1 flex flex-col justify-between p-4 sm:p-6 md:p-10 relative">
          
          {/* Fondo sutil con cuadrícula y resplandor de ciberseguridad */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(6,182,212,0.15),rgba(255,255,255,0))] pointer-events-none" />

          {/* Barra superior institucional del TFM */}
          <div className="max-w-4xl w-full mx-auto flex items-center justify-between text-xs z-10 pb-4 border-b border-slate-800/80">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <span className="font-bold text-white tracking-tight">TFM · Ciberseguridad</span>
                <span className="mx-2 text-slate-600">|</span>
                <span className="text-slate-400">Security Dashboard con MFA Adaptativo</span>
              </div>
            </div>

            <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Zero-Trust Auth</span>
            </div>
          </div>

          {/* Área Central: Renderizado del componente correspondiente según el paso del flujo */}
          <div className="my-auto py-8 z-10">
            {currentView === 'login' && (
              <LoginForm 
                onRequireMfa={handleRequireMfa}
                onLoginSuccess={handleLoginSuccess}
                onOpenEnrollment={() => setCurrentView('enrollment')}
                onAccountCreatedAndEnrolling={handleAccountCreatedAndEnrolling}
              />
            )}

            {currentView === 'mfa_challenge' && (
              <TotpVerification 
                userSession={userSession}
                onSuccess={handleMfaSuccess}
                onCancel={() => {
                  setUserSession(null);
                  setCurrentView('login');
                }}
                onGoToEnrollment={() => setCurrentView('enrollment')}
              />
            )}

            {currentView === 'enrollment' && (
              <TotpEnrollment 
                userEmail={userSession?.email || 'nuevo.usuario@ciberseguridad.es'}
                onEnrollmentComplete={handleEnrollmentComplete}
                onCancel={() => setCurrentView(userSession ? 'mfa_challenge' : 'login')}
              />
            )}
          </div>

          {/* Banner de Privacidad por Diseño (Art. 25 y 32 RGPD) */}
          <div className="max-w-2xl mx-auto w-full text-center text-xs text-slate-500 z-10 pt-4">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-[11px] text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Privacidad RGPD: Los logs y huellas están anonimizados mediante SHA-256. No se procesan ni almacenan IPs ni PII.</span>
            </div>
          </div>

        </div>
      )}

    </div>
  );
}
