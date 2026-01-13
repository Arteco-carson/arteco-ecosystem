import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Homepage from './components/Homepage';
import ArtworkList from './components/ArtworkList'; 
import ArtworkDetails from './components/ArtworkDetails';
import ArtistList from './components/ArtistList';
import ArtistDetails from './components/ArtistDetails';
import AppraisalList from './components/AppraisalList';
import AddAppraisal from './components/AddAppraisal';
import CollectionsList from './components/CollectionsList';
import CreateCollection from './components/CreateCollection';
import Profile from './components/Profile';
import AuditLogs from './components/AuditLogs';
import MainLayout from './components/MainLayout';
//Push build
// Checks for the session token (ISO27001 Compliance)
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

function App() {
  return (
    <Router>
      <Routes>
        {/* Public Authentication - No Navbar/Layout */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        
        {/* All Managed Routes wrapped in MainLayout */}
        <Route 
          path="/*" 
          element={
            <ProtectedRoute>
              <MainLayout>
                <Routes>
                  <Route path="/home" element={<Homepage />} />
                  <Route path="/collections" element={<CollectionsList />} />
                  <Route path="/collections/new" element={<CreateCollection />} />
                  <Route path="/artworks" element={<ArtworkList />} />
                  <Route path="/artwork/:id" element={<ArtworkDetails />} />
                  <Route path="/artists" element={<ArtistList />} />
                  <Route path="/artist/:id" element={<ArtistDetails />} />
                  <Route path="/appraisals" element={<AppraisalList />} />
                  <Route path="/add-appraisal" element={<AddAppraisal />} />
                  <Route path="/add-appraisal/:artworkId" element={<AddAppraisal />} />
                  <Route path="/profile" element={<Profile />} />
                  <Route path="/audit-logs" element={<AuditLogs />} />
                  
                  {/* Default redirection */}
                  <Route path="/" element={<Navigate to="/home" replace />} />
                  <Route path="*" element={<Navigate to="/home" replace />} />
                </Routes>
              </MainLayout>
            </ProtectedRoute>
          } 
        />
      </Routes>
    </Router>
  );
}

export default App;