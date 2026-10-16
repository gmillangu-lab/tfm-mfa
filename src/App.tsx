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
    <div className="min-h-screen flex flex-col font-sans bg-gradient-to-br from-sky-100/80 via-blue-50/60 to-slate-100 text-slate-800 selection:bg-sky-500 selection:text-white">
      
      {/* Toast de notificación flotante */}
      {notification && (
        <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50">
          <div className="bg-white/95 border border-sky-200 text-slate-800 px-4 py-2.5 rounded-xl shadow-xl shadow-sky-950/10 text-xs font-semibold flex items-center gap-2 backdrop-blur-md animate-in fade-in slide-in-from-top-2 duration-200">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{notification}</span>
          </div>
        </div>
      )}

      {/* RENDERIZADO DEL DASHBOARD: ÚNICAMENTE SI ESTÁ AUTENTICADO Y VERIFICADO */}
      {currentView === 'dashboard' && isAuthorizedForDashboard ? (
        <Dashboard 
          userSession={userSession}
          onLogout={handleLogout}
        />
      ) : (
        /* Vistas de Autenticación Previa (Login, Registro, Reto MFA, Enrolamiento) */
        <div className="flex-1 flex flex-col justify-between p-4 sm:p-6 md:p-8 relative">
          
          {/* Fondo sutil azul blanco con suaves gradientes */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_-10%,rgba(186,230,253,0.45),rgba(255,255,255,0))] pointer-events-none" />

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
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/85 border border-sky-200/80 text-[11px] text-slate-600 shadow-sm backdrop-blur-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>Privacidad RGPD: Los logs y huellas están anonimizados mediante SHA-256. Sin almacenamiento de IP ni PII.</span>
            </div>
          </div>

        </div>
      )}

    </div>
  );
}
