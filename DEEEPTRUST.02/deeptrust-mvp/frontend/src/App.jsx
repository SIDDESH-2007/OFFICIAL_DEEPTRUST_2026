import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Startup from './pages/Startup';
import Login from './pages/Login';
import Register from './pages/Register';
import FaceAuth from './pages/FaceAuth';
import Dashboard from './pages/Dashboard';

function ProtectedRoute({ children }) {
  const token = localStorage.getItem('deeptrust_token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/startup" replace />} />
      <Route path="/startup" element={<Startup />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/face-auth" element={<FaceAuth />} />
      <Route
        path="/dashboard"
        element={(
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        )}
      />
      <Route path="*" element={<Navigate to="/startup" replace />} />
    </Routes>
  );
}
