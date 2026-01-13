import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Image as ImageIcon, AlertCircle, Trash2 } from 'lucide-react';
import { Button, ConfigProvider, Modal } from 'antd';
import AddArtworkModal from './AddArtworkModal';
import API_URL from './api';

function ArtworkList() {
  const navigate = useNavigate();
  const [artworks, setArtworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isModalVisible, setIsModalVisible] = useState(false);

  const fetchArtworks = useCallback(async () => {
    const token = localStorage.getItem('token');
    
    if (!token) {
        navigate('/login');
        return;
    }

    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/api/artworks/user`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token.trim()}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setArtworks(data);
      } else if (response.status === 401) {
        localStorage.removeItem('token');
        navigate('/login');
      } else {
        setError('Unauthorized: Management credentials insufficient for this registry.');
      }
    } catch (err) {
      setError('System Error: Management server at port 7056 is unreachable.');
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchArtworks();
  }, [fetchArtworks]);

  const handleArtworkCreated = () => {
    fetchArtworks(); // Re-fetch artworks to show the newly added one
  };

  const handleDeleteArtwork = (artworkId) => {
    Modal.confirm({
      title: 'Delete Artwork',
      content: 'Are you sure you want to delete this artwork? This action cannot be undone.',
      okText: 'Delete',
      okType: 'danger',
      cancelText: 'Cancel',
      onOk: async () => {
        const token = localStorage.getItem('token');
        if (!token) return;

        try {
          const response = await fetch(`${API_URL}/api/artworks/${artworkId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token.trim()}` }
          });

          if (response.ok) fetchArtworks();
          else setError('Failed to delete artwork.');
        } catch (err) {
          setError('System Error: Could not delete artwork.');
        }
      }
    });
  };

  if (loading) return <div style={{ textAlign: 'center', padding: '40px' }}>Loading Artwork Inventory...</div>;

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
    <div style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h2 style={{ color: '#1e293b', margin: 0 }}>Artworks</h2>
        <Button 
          type="primary"
          icon={<Plus size={18} />}
          style={{ backgroundColor: '#246A73', borderColor: '#246A73' }}
          onClick={() => setIsModalVisible(true)}
        >
           Add Artwork
        </Button>
      </div>

      {error && (
        <div style={{ backgroundColor: '#fef2f2', border: '1px solid #fee2e2', padding: '15px', borderRadius: '8px', color: '#b91c1c', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <AlertCircle size={20} /> {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '25px' }}>
        {artworks.map((art) => (
          <div key={art.artworkId} style={{ backgroundColor: 'white', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0' }}>
            {art.imageUrl ? (
              <img src={art.imageUrl} alt={art.title} style={{ width: '100%', height: '200px', objectFit: 'contain', backgroundColor: '#f1f5f9' }} />
            ) : (
              <div style={{ height: '200px', backgroundColor: '#f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                 <ImageIcon size={40} color="#cbd5e1" />
              </div>
            )}
            <div style={{ padding: '15px' }}>
              <h4 style={{ margin: '0 0 5px 0', color: '#1e293b' }}>{art.title}</h4>
              <p style={{ margin: 0, fontSize: '0.85rem', color: '#64748b' }}>Collector Access Only</p>
              <div style={{ marginTop: '15px', paddingTop: '15px', borderTop: '1px solid #f1f5f9', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 'bold', color: '#059669' }}>
                  £{art.acquisitionCost?.toLocaleString('en-GB', { minimumFractionDigits: 2 })}
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <Button 
                    type="link"
                    onClick={() => navigate(`/artwork/${art.artworkId}`)}
                    style={{ padding: 0, fontWeight: '600', fontSize: '0.9rem' }}
                  >
                    View
                  </Button>
                  <Button 
                    type="primary"
                    icon={<Trash2 size={16} />}
                    style={{ backgroundColor: '#246A73', borderColor: '#246A73' }}
                    onClick={() => handleDeleteArtwork(art.artworkId)}
                  />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {!loading && artworks.length === 0 && !error && (
        <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
          No artworks currently registered in your inventory.
        </div>
      )}

      <AddArtworkModal
        open={isModalVisible}
        onClose={() => setIsModalVisible(false)}
        onArtworkCreated={handleArtworkCreated}
      />
    </div>
    </ConfigProvider>
  );
}

export default ArtworkList;