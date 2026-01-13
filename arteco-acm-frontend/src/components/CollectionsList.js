import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { Card, Col, Row, Spin, Typography, Select, Alert, Button, ConfigProvider, Modal, message } from 'antd';
import { useNavigate } from 'react-router-dom';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import API_URL from './api';

const { Title, Text } = Typography;
const { Option } = Select;

const CollectionsList = () => {
  const [artworks, setArtworks] = useState([]);
  const [collections, setCollections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedCollection, setSelectedCollection] = useState(null);
  const [isAddModalVisible, setIsAddModalVisible] = useState(false);
  const [unassignedArtworks, setUnassignedArtworks] = useState([]);
  const [selectedArtworkIds, setSelectedArtworkIds] = useState([]);
  const [addingArtworks, setAddingArtworks] = useState(false);
  const [messageApi, contextHolder] = message.useMessage();
  const navigate = useNavigate();

  // Unified Header Helper with explicit trimming for UK Management Console
  const getAuthHeader = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) return null;
    return { Authorization: `Bearer ${token.trim()}` };
  }, []);

  const fetchArtworksForCollection = useCallback(async (collectionId) => {
    try {
      const headers = getAuthHeader();
      if (!headers) {
        navigate('/login');
        return;
      }

      const res = await axios.get(`${API_URL}/api/artworks/user?collectionId=${collectionId}`, {
        headers
      });
      setArtworks(res.data);
      setError(null);
    } catch (err) {
      if (err.response?.status === 401) {
        setError("Security session expired. Please re-authenticate.");
        localStorage.removeItem('token');
        navigate('/login');
      } else {
        setError("Failed to retrieve collection artworks.");
      }
    }
  }, [getAuthHeader, navigate]);

  const handleDeleteCollection = () => {
    if (!selectedCollection) return;

    const hasArtworks = artworks.length > 0;
    const confirmMessage = hasArtworks 
      ? 'The artworks will be removed from the collection. Click OK to confirm or Cancel to not delete the Collection.'
      : 'Are you sure you want to delete this collection? This action cannot be undone.';

    Modal.confirm({
      title: 'Delete Collection',
      content: confirmMessage,
      okText: 'OK',
      okType: 'primary',
      cancelText: 'Cancel',
      onOk: async () => {
        try {
          const headers = getAuthHeader();
          await axios.delete(`${API_URL}/api/collections/${selectedCollection}`, { headers });
          
          const updatedCollections = collections.filter(c => c.collectionId !== selectedCollection);
          setCollections(updatedCollections);
          
          if (updatedCollections.length > 0) {
            const nextId = updatedCollections[0].collectionId;
            setSelectedCollection(nextId);
            sessionStorage.setItem('selectedCollection', nextId);
            fetchArtworksForCollection(nextId);
          } else {
            setSelectedCollection(null);
            sessionStorage.removeItem('selectedCollection');
            setArtworks([]);
          }
        } catch (err) {
          console.error("Delete Error:", err);
          setError("Failed to delete collection. Ensure it is not locked by governance policies.");
        }
      }
    });
  };

  const fetchUnassignedArtworks = useCallback(async () => {
    try {
        const headers = getAuthHeader();
        const res = await axios.get(`${API_URL}/api/artworks/user?unassigned=true`, { headers });
        setUnassignedArtworks(res.data);
    } catch (err) {
        console.error("Failed to fetch unassigned artworks", err);
    }
  }, [getAuthHeader]);

  const handleAddArtworksToCollection = async () => {
      if (selectedArtworkIds.length === 0) return;
      setAddingArtworks(true);
      try {
          const headers = getAuthHeader();
          await axios.post(`${API_URL}/api/collections/${selectedCollection}/artworks`, selectedArtworkIds, { headers });
          messageApi.success('Artworks added to collection.');
          setIsAddModalVisible(false);
          fetchArtworksForCollection(selectedCollection);
      } catch (err) {
          messageApi.error('Failed to add artworks.');
      } finally {
          setAddingArtworks(false);
      }
  };

  // Initial fetch for the collections dropdown
  useEffect(() => {
    const fetchInitialData = async () => {
      setLoading(true);
      try {
        const headers = getAuthHeader();
        if (!headers) {
          navigate('/login');
          return;
        }

        const res = await axios.get(`${API_URL}/api/collections`, { headers });
        setCollections(res.data);
        
        // Check session storage for a previously selected collection
        const savedCollectionId = sessionStorage.getItem('selectedCollection');
        
        let initialCollectionId = null;
        if (savedCollectionId && res.data.some(c => c.collectionId === parseInt(savedCollectionId, 10))) {
          initialCollectionId = parseInt(savedCollectionId, 10);
        } else if (res.data.length > 0) {
          initialCollectionId = res.data[0].collectionId;
        }

        if (initialCollectionId) {
          setSelectedCollection(initialCollectionId);
          await fetchArtworksForCollection(initialCollectionId);
        }

      } catch (err) {
        console.error("Governance Registry Fetch Error:", err);
        if (err.response?.status === 401) {
          setError("Security session expired. Please re-authenticate.");
          localStorage.removeItem('token');
          navigate('/login');
        } else {
          setError("Could not load collection registry.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchInitialData();
  }, [getAuthHeader, navigate, fetchArtworksForCollection]);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '100px' }}>
        {/* Fixed Spin Warning: Wrapping in a div makes it a "nested" pattern */}
        <Spin size="large">
          <div style={{ marginTop: '20px' }}>Validating Management Credentials...</div>
        </Spin>
      </div>
    );
  }

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
    {contextHolder}
    <div style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <Title level={2} style={{ color: '#1e293b', margin: 0 }}>Collections</Title>
        <div style={{ display: 'flex', gap: '10px' }}>
          <Button 
              type="primary"
              icon={<DeleteOutlined />}
              onClick={handleDeleteCollection}
              disabled={!selectedCollection}
          >
              Delete Collection
          </Button>
          <Button 
              type="primary"
              onClick={() => {
                  fetchUnassignedArtworks();
                  setSelectedArtworkIds([]);
                  setIsAddModalVisible(true);
              }}
              disabled={!selectedCollection}
          >
              Add Artwork to Collection
          </Button>
          <Button 
              type="primary" 
              icon={<PlusOutlined />}
              onClick={() => navigate('/collections/new')}
          >
              Create Collection
          </Button>
        </div>
      </div>
      
      <div style={{ marginBottom: '30px', display: 'flex', alignItems: 'center', gap: '15px' }}>
        <Text strong>Select Registry:</Text>
        <Select
          style={{ width: 300 }}
          value={selectedCollection}
          placeholder="Select a collection"
          onChange={(value) => {
            setSelectedCollection(value);
            sessionStorage.setItem('selectedCollection', value);
            fetchArtworksForCollection(value);
          }}
        >
          {collections.map((c) => (
            <Option key={c.collectionId} value={c.collectionId}>{c.collectionName}</Option>
          ))}
        </Select>
      </div>

      {/* Fixed Alert Warning: Changed 'message' to 'description' and added 'title' */}
      {error && (
        <Alert 
          title="Security Protocol Alert"
          description={error} 
          type="error" 
          showIcon 
          style={{ marginBottom: '20px' }} 
        />
      )}

      <Row gutter={[24, 24]}>
        {artworks.map((art) => (
          <Col xs={24} sm={12} md={8} lg={6} key={art.artworkId}>
            <Card
              hoverable
              cover={
                art.imageUrl ? (
                  <img alt={art.title} src={art.imageUrl} style={{ height: 200, objectFit: 'contain', width: '100%', backgroundColor: '#f1f5f9' }} />
                ) : (
                  <div style={{ height: 200, background: '#f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Text type="secondary">No Image Available</Text>
                  </div>
                )
              }
              onClick={() => navigate(`/artwork/${art.artworkId}`)}
            >
              <Card.Meta 
                title={art.title} 
                description={
                  <div style={{ marginTop: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Text strong style={{ color: '#059669' }}>
                      £{art.acquisitionCost?.toLocaleString('en-GB', { minimumFractionDigits: 2 })}
                    </Text>
                    <Button 
                      type="link"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/artwork/${art.artworkId}`);
                      }}
                      style={{ padding: 0, fontWeight: '600', fontSize: '0.9rem' }}
                    >
                      View
                    </Button>
                  </div>
                } 
              />
            </Card>
          </Col>
        ))}
      </Row>

      {!loading && artworks.length === 0 && !error && (
        <div style={{ textAlign: 'center', marginTop: '40px', color: '#64748b' }}>
          No artworks found in the selected collection.
        </div>
      )}

      <Modal
        title="Add Artworks to Collection"
        open={isAddModalVisible}
        onCancel={() => setIsAddModalVisible(false)}
        onOk={handleAddArtworksToCollection}
        confirmLoading={addingArtworks}
        okText="Add Selected"
      >
        <p>Select artworks to add to the current collection:</p>
        <Select
            mode="multiple"
            style={{ width: '100%' }}
            placeholder="Select artworks"
            value={selectedArtworkIds}
            onChange={setSelectedArtworkIds}
            optionFilterProp="children"
        >
            {unassignedArtworks.map(art => (
                <Option key={art.artworkId} value={art.artworkId}>{art.title} ({art.artistName})</Option>
            ))}
        </Select>
        {unassignedArtworks.length === 0 && <div style={{ marginTop: 10, color: '#999' }}>No unassigned artworks found.</div>}
      </Modal>
    </div>
    </ConfigProvider>
  );
};

export default CollectionsList;