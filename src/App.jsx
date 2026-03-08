import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar      from './components/Navbar';
import Footer      from './components/Footer';
import HomePage    from './pages/HomePage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex flex-col min-h-screen bg-cyber-bg font-mono text-cyber-text">
        <Navbar />
        <main className="flex-1 flex flex-col">
          <Routes>
            <Route path="/"        element={<HomePage />} />
            <Route path="/scan"    element={<DashboardPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
}
