import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { 
    Layout, 
    LogOut, 
    Database, 
    History, 
    Home, 
    User, 
    FolderOpen, 
    Users 
} from 'lucide-react';

const Navbar = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const token = localStorage.getItem('token');

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    if (!token) return null;

    // Helper to highlight active link based on current path
    const isActive = (path) => location.pathname === path;

    const linkStyle = (path) => ({
        color: isActive(path) ? '#3b82f6' : '#cbd5e1',
        textDecoration: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '0.9rem',
        fontWeight: '500',
        transition: 'color 0.2s'
    });

    return (
        <nav style={{ 
            backgroundColor: '#246A73', 
            padding: '0 30px', 
            height: '64px', 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            color: 'white',
            boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1)',
            zIndex: 1000
        }}>
            {/* Branding Section */}
            <div 
                style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }} 
                onClick={() => navigate('/home')}
            >
                <div style={{ backgroundColor: '#3b82f6', padding: '6px', borderRadius: '8px' }}>
                    <Layout size={20} color="white" />
                </div>
                <span style={{ fontWeight: 'bold', fontSize: '1.25rem', letterSpacing: '-0.5px' }}>
                    Arteco Collection Manager
                </span>
            </div>
            
            {/* Navigation Links */}
            <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                <Link to="/home" style={linkStyle('/home')}>
                    <Home size={18} /> Home
                </Link>
                
                <Link to="/collections" style={linkStyle('/collections')}>
                    <FolderOpen size={18} /> Collections
                </Link>
                
                <Link to="/artworks" style={linkStyle('/artworks')}>
                    <Database size={18} /> Artworks
                </Link>

                <Link to="/artists" style={linkStyle('/artists')}>
                    <Users size={18} /> Artists
                </Link>
                
                <Link to="/appraisals" style={linkStyle('/appraisals')}>
                    <History size={18} /> Appraisals
                </Link>
                
                <Link to="/profile" style={linkStyle('/profile')}>
                    <User size={18} /> Profile
                </Link>
                
                {/* Visual Separator */}
                <div style={{ height: '20px', width: '1px', backgroundColor: '#334155', margin: '0 5px' }} />
                
                <button 
                    onClick={handleLogout} 
                    style={{ 
                        background: '#ef4444', 
                        color: 'white', 
                        border: 'none', 
                        padding: '8px 16px', 
                        borderRadius: '6px', 
                        cursor: 'pointer', 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px',
                        fontWeight: '600'
                    }}
                >
                    <LogOut size={16} /> Logout
                </button>
            </div>
        </nav>
    );
};

export default Navbar;