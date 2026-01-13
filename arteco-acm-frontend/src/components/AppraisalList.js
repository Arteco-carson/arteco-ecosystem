import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { History, Calendar, User, FileText, Plus } from 'lucide-react';
import { Button } from 'antd';
import API_URL from './api';

function AppraisalList() {
  const [appraisals, setAppraisals] = useState([]);
  const [loading, setLoading] = useState(true);
  const token = localStorage.getItem('token');
  const navigate = useNavigate();

  useEffect(() => {
    fetch(`${API_URL}/api/appraisals`, {
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
      .then(res => {
        if (!res.ok) throw new Error('Could not retrieve filtered records.');
        return res.json();
      })
      .then(data => {
        setAppraisals(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Management Registry Fetch Error:", err);
        setLoading(false);
      });
  }, [token]);

  if (loading) return <div style={{ textAlign: 'center', padding: '40px' }}>Loading Personal Valuation Registry...</div>;

  return (
    <div style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '25px' }}>
        <h2 style={{ color: '#1e293b', display: 'flex', alignItems: 'center', gap: '10px', margin: 0 }}>
          <History size={28} /> My Artwork's Valuations
        </h2>
        <Button 
          type="primary"
          icon={<Plus size={18} />}
          style={{ backgroundColor: '#246A73', borderColor: '#246A73' }}
          onClick={() => navigate('/add-appraisal')}
        >
           Add Appraisal
        </Button>
      </div>

      <div style={{ backgroundColor: 'white', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 4px 6px rgba(0,0,0,0.05)', border: '1px solid #e2e8f0' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead style={{ backgroundColor: '#f8fafc', borderBottom: '2px solid #edf2f7' }}>
            <tr>
              <th style={{ padding: '15px', color: '#64748b', fontSize: '0.85rem', textTransform: 'uppercase' }}>Asset ID</th>
              <th style={{ padding: '15px', color: '#64748b', fontSize: '0.85rem', textTransform: 'uppercase' }}>Collection Item</th>
              <th style={{ padding: '15px', color: '#64748b', fontSize: '0.85rem', textTransform: 'uppercase' }}>Appraiser</th>
              <th style={{ padding: '15px', color: '#64748b', fontSize: '0.85rem', textTransform: 'uppercase' }}>Date</th>
              <th style={{ padding: '15px', color: '#64748b', fontSize: '0.85rem', textTransform: 'uppercase', textAlign: 'right' }}>Market Value</th>
            </tr>
          </thead>
          <tbody>
            {appraisals.length > 0 ? (
              appraisals.map(app => (
                <tr key={app.appraisalId} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ padding: '15px', fontWeight: 'bold', color: '#3b82f6' }}>#{app.artworkId}</td>
                  <td style={{ padding: '15px', color: '#1e293b', fontWeight: '600' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <FileText size={16} color="#94a3b8" />
                      {app.artworkTitle}
                    </div>
                  </td>
                  <td style={{ padding: '15px', color: '#475569' }}>
                    <User size={14} style={{ marginRight: '5px', verticalAlign: 'middle' }}/> {app.appraiserName}
                  </td>
                  <td style={{ padding: '15px', color: '#475569' }}>
                    <Calendar size={14} style={{ marginRight: '5px', verticalAlign: 'middle' }}/> 
                    {new Date(app.valuationDate).toLocaleDateString('en-GB')}
                  </td>
                  <td style={{ padding: '15px', textAlign: 'right', fontWeight: 'bold', color: '#059669' }}>
                    {app.currencyCode} {app.valuationAmount?.toLocaleString('en-GB', { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                  No appraisal records found for your owned assets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AppraisalList;