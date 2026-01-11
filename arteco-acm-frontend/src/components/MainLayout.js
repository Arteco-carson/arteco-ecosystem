import React from 'react';
import Navbar from './Navbar';

const MainLayout = ({ children }) => {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* The Navbar is now the fixed header of this layout */}
      <Navbar />
      
      {/* The main content area where your pages will render */}
      <main style={{ 
        flex: 1, 
        padding: '40px 20px', 
        backgroundColor: '#f8fafc', // Light grey professional background
        overflowY: 'auto' 
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
          {children}
        </div>
      </main>
    </div>
  );
};

export default MainLayout;