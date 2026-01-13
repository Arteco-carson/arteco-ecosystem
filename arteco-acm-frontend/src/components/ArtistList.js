import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Globe, ExternalLink, Plus } from 'lucide-react';
import { Button, ConfigProvider } from 'antd';
import AddArtistModal from './AddArtistModal';
import API_URL from './api';

function ArtistList() {
  const navigate = useNavigate();
  const [artists, setArtists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [failedImages, setFailedImages] = useState(new Set());
  
  const token = localStorage.getItem('token'); 

  const fetchArtists = useCallback(() => {
    setLoading(true);
    fetch(`${API_URL}/api/artworks/user/artists`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
      .then(res => res.json())
      .then(data => {
        setArtists(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Fetch Error:", err);
        setLoading(false);
      });
  }, [token]);

  useEffect(() => {
    fetchArtists();
  }, [fetchArtists]);

  const handleArtistCreated = () => {
    fetchArtists();
  };

  const handleImageError = (artistId) => {
    setFailedImages(prev => {
      const newSet = new Set(prev);
      newSet.add(artistId);
      return newSet;
    });
  };

  if (loading) return <div style={{ textAlign: 'center', padding: '40px' }}>Loading Artist Registry...</div>;

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
          <h2 style={{ color: '#1e293b', margin: 0 }}>Artists</h2>
          <Button type="primary" icon={<Plus />} onClick={() => setIsModalVisible(true)}>
              Add New Artist
          </Button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '25px' }}>
        {artists.map(artist => (
            <div key={artist.artistId} style={{ backgroundColor: 'white', padding: '25px', borderRadius: '15px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)', border: '1px solid #f1f5f9', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '15px' }}>
                <div style={{ width: '50px', height: '50px', borderRadius: '10px', overflow: 'hidden', backgroundColor: '#f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    {artist.profileImageUrl && !failedImages.has(artist.artistId) ? (
                        <img 
                          src={artist.profileImageUrl} 
                          alt={`${artist.firstName} ${artist.lastName}`} 
                          style={{ width: '100%', height: '100%', objectFit: 'cover' }} 
                          onError={() => handleImageError(artist.artistId)}
                        />
                    ) : (
                        <User size={24} color="#64748b" />
                    )}
                </div>
                <div>
                    <h3 style={{ margin: 0, color: '#1e293b' }}>{artist.firstName} {artist.lastName}</h3>
                    <span style={{ fontSize: '0.85rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Globe size={14} /> {artist.nationality}
                    </span>
                </div>
                </div>
            </div>
            <div style={{ borderTop: '1px solid #edf2f7', paddingTop: '15px', display: 'flex', justifyContent: 'flex-end' }}>
                <Button type="link" icon={<ExternalLink size={16} />} onClick={() => navigate(`/artist/${artist.artistId}`)} style={{ fontWeight: 600 }}>
                  View Profile & Works
                </Button>
            </div>
            </div>
        ))}
        </div>
        {!loading && artists.length === 0 && (
          <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
            No artists currently registered.
          </div>
        )}
        <AddArtistModal
            visible={isModalVisible}
            onClose={() => setIsModalVisible(false)}
            onArtistCreated={handleArtistCreated}
        />
    </div>
    </ConfigProvider>
  );
}

export default ArtistList;