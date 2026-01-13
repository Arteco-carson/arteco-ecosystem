import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button, ConfigProvider } from 'antd';
import { User, Mail, Lock, ChevronLeft, UserCircle, Tag } from 'lucide-react';
import API_URL from './api';

function Register() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    username: '',
    email: '',
    password: '',
    roleId: 1,
    marketingConsent: false
  });
  const [error, setError] = useState('');
  const [roles, setRoles] = useState([
    { roleId: 1, roleName: 'Guest' },
    { roleId: 2, roleName: 'Manager (Operations)' },
    { roleId: 3, roleName: 'Admin (IT/Head of Ops)' }
  ]);

  useEffect(() => {
    const fetchRoles = async (retries = 3) => {
      try {
        const response = await fetch(`${API_URL}/api/userroles`);
        if (response.ok) {
          const data = await response.json();
          if (data && data.length > 0) {
            setRoles(data);
            return;
          }
        }
        throw new Error(`Status: ${response.status}`);
      } catch (err) {
        if (retries > 0) {
          // Retry with backoff (500ms, 1000ms, 2000ms) to handle cold starts
          setTimeout(() => fetchRoles(retries - 1), 500 * Math.pow(2, 3 - retries));
        } else {
          console.warn('Could not fetch roles dynamically, using defaults.');
        }
      }
    };
    fetchRoles();
  }, []);

  const inputStyle = {
    width: '100%',
    padding: '12px 12px 12px 40px',
    borderRadius: '8px',
    border: '1px solid #cbd5e1',
    boxSizing: 'border-box',
    fontSize: '1rem'
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Prepare payload to match the backend RegistrationRequest.cs
    const registrationPayload = {
      firstName: formData.firstName,
      lastName: formData.lastName,
      username: formData.username,
      email: formData.email,
      password: formData.password,
      externalUserId: formData.email, // Using email as the unique external ID
      roleId: parseInt(formData.roleId, 10),
      userTypeId: 2,
      marketingConsent: formData.marketingConsent
    };

    try {
      const response = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registrationPayload),
      });

      if (response.ok) {
        navigate('/login', { state: { message: 'Profile created successfully. Please log in.' } });
      } else {
        try {
          const data = await response.json();
          setError(data.message || 'Registration failed. Please check your details.');
        } catch (parseError) {
          // Fallback if the 500 error returns HTML (common in IIS/Azure)
          setError(`Server Error (${response.status}): Please contact support.`);
        }
      }
    } catch (err) {
      setError('System Error: Could not connect to the registration service.');
    }
  };

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
    <div style={{ maxWidth: '500px', margin: '50px auto', padding: '20px', boxSizing: 'border-box' }}>
      <div style={{ backgroundColor: 'white', padding: '30px', borderRadius: '15px', boxShadow: '0 10px 25px rgba(0,0,0,0.05)', width: '100%', boxSizing: 'border-box' }}>
        <div style={{ textAlign: 'center', marginBottom: '25px' }}>
          <UserCircle size={48} color="#3b82f6" style={{ marginBottom: '10px' }} />
          <h2 style={{ color: '#1e293b', margin: 0 }}>Register Profile</h2>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>Arteco Operations Enrolment</p>
        </div>

        {error && (
          <div style={{ color: '#e74c3c', backgroundColor: '#fdf2f2', padding: '12px', borderRadius: '8px', marginBottom: '20px', fontSize: '0.85rem', border: '1px solid #fee2e2' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ display: 'flex', gap: '15px', marginBottom: '20px' }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>First Name</label>
              <div style={{ position: 'relative' }}>
                <User size={18} style={{ position: 'absolute', left: '12px', top: '12px', color: '#94a3b8' }} />
                <input 
                  type="text" required
                  style={inputStyle}
                  value={formData.firstName}
                  onChange={(e) => setFormData({...formData, firstName: e.target.value})}
                />
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>Last Name</label>
              <div style={{ position: 'relative' }}>
                <User size={18} style={{ position: 'absolute', left: '12px', top: '12px', color: '#94a3b8' }} />
                <input 
                  type="text" required
                  style={inputStyle}
                  value={formData.lastName}
                  onChange={(e) => setFormData({...formData, lastName: e.target.value})}
                />
              </div>
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>Username</label>
            <div style={{ position: 'relative' }}>
              <Tag size={18} style={{ position: 'absolute', left: '12px', top: '12px', color: '#94a3b8' }} />
              <input 
                type="text" required
                style={inputStyle}
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
              />
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>Work Email</label>
            <div style={{ position: 'relative' }}>
              <Mail size={18} style={{ position: 'absolute', left: '12px', top: '12px', color: '#94a3b8' }} />
              <input 
                type="email" required
                style={inputStyle}
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
              />
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={18} style={{ position: 'absolute', left: '12px', top: '12px', color: '#94a3b8' }} />
              <input 
                type="password" required
                autoComplete="new-password"
                style={inputStyle}
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
              />
            </div>
          </div>

          <div style={{ marginBottom: '25px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.85rem' }}>System Role</label>
            <select 
              style={{ ...inputStyle, paddingLeft: '12px', backgroundColor: '#f8fafc' }}
              value={formData.roleId}
              onChange={(e) => setFormData({...formData, roleId: e.target.value})}
            >
              {roles.map(role => (
                <option key={role.roleId} value={role.roleId}>
                  {role.roleName}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', marginBottom: '30px' }}>
            <input 
              type="checkbox" 
              id="marketing"
              style={{ marginTop: '4px' }}
              checked={formData.marketingConsent}
              onChange={(e) => setFormData({...formData, marketingConsent: e.target.checked})}
            />
            <label htmlFor="marketing" style={{ fontSize: '0.8rem', color: '#64748b', lineHeight: '1.4' }}>
              I consent to the processing of my data for system notifications and internal audit compliance (GDPR).
            </label>
          </div>

          <Button type="primary" htmlType="submit" block size="large" style={{ fontWeight: 'bold', height: 'auto', padding: '10px' }}>
            Register Account
          </Button>
        </form>

        <Link to="/login" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px', textDecoration: 'none', color: '#64748b', fontSize: '0.85rem', marginTop: '25px' }}>
          <ChevronLeft size={16} /> Already have a profile? Login
        </Link>
      </div>
    </div>
    </ConfigProvider>
  );
}

export default Register;