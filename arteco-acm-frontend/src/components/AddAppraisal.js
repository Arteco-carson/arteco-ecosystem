import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ChevronLeft, BadgePoundSterling, Save, User, Palette, Loader2 } from 'lucide-react';
import API_URL from './api';

function AddAppraisal() {
  const { artworkId } = useParams();
  const navigate = useNavigate();
  const token = localStorage.getItem('token');
  
  const [artworks, setArtworks] = useState([]);
  const [artworkName, setArtworkName] = useState('');
  const [formData, setFormData] = useState({
    artworkId: artworkId || '',
    valuationAmount: '',
    insuranceValue: '',
    valuationDate: new Date().toISOString().split('T')[0],
    appraiserName: '',
    notes: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!token) {
      navigate('/login');
      return;
    }

    fetch(`${API_URL}/api/artworks`, {
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
      .then(res => res.json())
      .then(data => {
        setArtworks(data);
        if (artworkId) {
          const selected = data.find(a => String(a.id || a.artworkId) === String(artworkId));
          if (selected) setArtworkName(selected.title);
        }
      })
      .catch(err => console.error("Could not retrieve artworks:", err));
  }, [artworkId, token, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    const numericValuation = parseFloat(formData.valuationAmount);
    const selectedId = parseInt(formData.artworkId);

    const appraisalPayload = {
      ...formData,
      artworkId: selectedId,
      valuationAmount: numericValuation,
      insuranceValue: numericValuation 
    };

    try {
      // Step A: Save Appraisal Record (Verified Working)
      const appraisalResponse = await fetch(`${API_URL}/api/appraisals`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify(appraisalPayload),
      });

      if (appraisalResponse.ok) {
        navigate(`/artwork/${selectedId}`); 
        return;
      }
    } catch (error) {
      console.error("Submission Error:", error);
      alert("System Error: Failed to communicate with the management server.");
    }
    
    setIsSubmitting(false);
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', padding: '20px' }}>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
      <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '5px' }}>
        <ChevronLeft size={20} /> Back to Details
      </button>

      <div style={{ backgroundColor: 'white', padding: '40px', borderRadius: '15px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0' }}>
        <div style={{ marginBottom: '30px', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', padding: '12px', backgroundColor: '#f1f5f9', borderRadius: '50%', marginBottom: '15px' }}>
            <BadgePoundSterling size={32} color="#2c3e50" />
          </div>
          <h2 style={{ color: '#1e293b', margin: '0 0 5px 0' }}>Artwork Valuation Update</h2>
          <p style={{ color: '#64748b', fontSize: '1.1rem', fontWeight: '500' }}>
            {artworkName ? `Asset: ${artworkName}` : 'Loading...'}
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.9rem', color: '#475569' }}>Select Artwork</label>
            <div style={{ position: 'relative' }}>
              <Palette size={18} style={{ position: 'absolute', left: '12px', top: '14px', color: '#94a3b8' }} />
              <select 
                required
                style={{ width: '100%', padding: '12px 12px 12px 40px', borderRadius: '8px', border: '1px solid #cbd5e1', boxSizing: 'border-box', backgroundColor: 'white' }}
                value={formData.artworkId}
                onChange={(e) => {
                  const id = e.target.value;
                  setFormData({...formData, artworkId: id});
                  const selected = artworks.find(a => String(a.id || a.artworkId) === id);
                  if (selected) setArtworkName(selected.title);
                }}
              >
                <option value="">-- Select Artwork --</option>
                {artworks.map(art => (
                  <option key={art.id || art.artworkId} value={art.id || art.artworkId}>{art.title}</option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.9rem', color: '#475569' }}>New Acquisition Cost (£)</label>
            <input 
              type="number" required step="0.01"
              style={{ width: '100%', padding: '12px', borderRadius: '8px', border: '1px solid #cbd5e1', boxSizing: 'border-box' }}
              value={formData.valuationAmount}
              onChange={(e) => setFormData({...formData, valuationAmount: e.target.value})}
            />
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.9rem', color: '#475569' }}>Appraiser Name</label>
            <div style={{ position: 'relative' }}>
              <User size={18} style={{ position: 'absolute', left: '12px', top: '14px', color: '#94a3b8' }} />
              <input 
                type="text" required
                style={{ width: '100%', padding: '12px 12px 12px 40px', borderRadius: '8px', border: '1px solid #cbd5e1', boxSizing: 'border-box' }}
                value={formData.appraiserName}
                onChange={(e) => setFormData({...formData, appraiserName: e.target.value})}
              />
            </div>
          </div>

          <div style={{ marginBottom: '30px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', fontSize: '0.9rem', color: '#475569' }}>Compliance Notes</label>
            <textarea 
              rows="4" 
              style={{ width: '100%', padding: '12px', borderRadius: '8px', border: '1px solid #cbd5e1', resize: 'vertical', boxSizing: 'border-box' }}
              value={formData.notes}
              onChange={(e) => setFormData({...formData, notes: e.target.value})}
            />
          </div>

          <button type="submit" disabled={isSubmitting} style={{ width: '100%', backgroundColor: isSubmitting ? '#94a3b8' : '#246A73', color: 'white', padding: '15px', borderRadius: '8px', border: 'none', fontWeight: 'bold', cursor: isSubmitting ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px', fontSize: '1rem' }}>
            {isSubmitting ? (
              <>
                <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                Processing...
              </>
            ) : (
              <>
                <Save size={18} /> Update Appraisal & Valuation
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

export default AddAppraisal;