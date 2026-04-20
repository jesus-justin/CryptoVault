import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Sidebar } from './components/Layout/Sidebar';
import { TopBar } from './components/Layout/TopBar';
import { useTheme } from './hooks/useTheme';
import CipherPlayground from './pages/CipherPlayground';
import Dashboard from './pages/Dashboard';
import FileEncryptor from './pages/FileEncryptor';
import HashAnalyzer from './pages/HashAnalyzer';
import JWTStudio from './pages/JWTStudio';
import KeyExchangeLab from './pages/KeyExchangeLab';
import KeyManager from './pages/KeyManager';
import SignatureVerifier from './pages/SignatureVerifier';

const queryClient = new QueryClient();

export default function App() {
  const { theme, toggleTheme } = useTheme();

  return (
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <BrowserRouter>
          <div className="min-h-screen bg-gradient-to-br from-slate-100 via-white to-cyan-50 text-slate-900 md:flex">
            <Sidebar />
            <main className="flex-1">
              <TopBar theme={theme} onToggleTheme={toggleTheme} requestId={undefined} />
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/cipher-playground" element={<CipherPlayground />} />
                <Route path="/key-manager" element={<KeyManager />} />
                <Route path="/hash-analyzer" element={<HashAnalyzer />} />
                <Route path="/file-encryptor" element={<FileEncryptor />} />
                <Route path="/jwt-studio" element={<JWTStudio />} />
                <Route path="/signature-verifier" element={<SignatureVerifier />} />
                <Route path="/key-exchange-lab" element={<KeyExchangeLab />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>
        </BrowserRouter>
      </ErrorBoundary>
    </QueryClientProvider>
  );
}
