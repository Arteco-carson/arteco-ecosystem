import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import API_URL from './api';
import { Form, Input, Button, Typography, message, Card, Transfer, ConfigProvider } from 'antd';
import { ChevronLeft } from 'lucide-react';
import { PlusOutlined } from '@ant-design/icons';
import AddArtworkModal from './AddArtworkModal';

const { Title } = Typography;
const { TextArea } = Input;

const CreateCollection = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [artworks, setArtworks] = useState([]);
  const [targetKeys, setTargetKeys] = useState([]);
  const [isModalVisible, setIsModalVisible] = useState(false);

  const getAuthHeader = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) return null;
    return { Authorization: `Bearer ${token.trim()}` };
  }, []);

  useEffect(() => {
    const fetchArtworks = async () => {
        try {
            const headers = getAuthHeader();
            if (!headers) {
                navigate('/login');
                return;
            }
            const res = await axios.get(`${API_URL}/api/artworks/user`, { headers });
            const formattedArtworks = res.data.map(art => ({
                key: art.artworkId.toString(),
                title: art.title,
                description: art.artistName,
            }));
            setArtworks(formattedArtworks);
        } catch (error) {
            console.error('Failed to fetch artworks:', error);
            message.error('Could not load artworks for selection.');
        }
    };

    fetchArtworks();
  }, [getAuthHeader, navigate]);

  const handleTransferChange = (newTargetKeys) => {
    setTargetKeys(newTargetKeys);
  };

  const handleSubmit = async (values) => {
    setLoading(true);
    try {
      const headers = getAuthHeader();
      if (!headers) {
        message.error('Authentication token not found. Please log in again.');
        navigate('/login');
        return;
      }

      const payload = {
          ...values,
          artworkIds: targetKeys.map(key => parseInt(key, 10)),
      };

      await axios.post(`${API_URL}/api/collections`, payload, { headers });
      message.success('Collection created successfully!');
      navigate('/collections');
    } catch (error) {
      console.error('Failed to create collection:', error);
      if (error.response?.status === 401) {
        message.error('Your session has expired. Please log in again.');
        navigate('/login');
      } else {
        message.error('Failed to create collection. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleArtworkCreated = (newArtwork) => {
    const formattedNewArtwork = {
        key: newArtwork.artworkId.toString(),
        title: newArtwork.title,
        description: newArtwork.artistName,
    };

    setArtworks(prev => [...prev, formattedNewArtwork]);
    setTargetKeys(prev => [...prev, formattedNewArtwork.key]);
    setIsModalVisible(false);
  };

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        <button 
            onClick={() => navigate('/collections')} 
            style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '5px', 
            background: 'none', 
            border: 'none', 
            color: '#64748b', 
            cursor: 'pointer', 
            marginBottom: '20px',
            padding: 0,
            fontSize: '0.95rem',
            fontWeight: '500'
            }}
        >
            <ChevronLeft size={20} /> Back to Collections
        </button>
      <Card>
        <Title level={2} style={{ marginBottom: '30px' }}>Create New Collection</Title>
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          autoComplete="off"
        >
          <Form.Item
            name="collectionName"
            label="Collection Name"
            rules={[{ required: true, message: 'Please input the collection name!' }]}
          >
            <Input placeholder="e.g., Modern Art" />
          </Form.Item>

          <Form.Item
            name="description"
            label="Description"
          >
            <TextArea rows={4} placeholder="A brief description of the collection" />
          </Form.Item>

          <Form.Item label="Add Artworks">
            <div style={{marginBottom: '10px'}}>
                <Button icon={<PlusOutlined size={14} />} onClick={() => setIsModalVisible(true)}>
                    Create New Artwork
                </Button>
            </div>
            <Transfer
                dataSource={artworks}
                targetKeys={targetKeys}
                onChange={handleTransferChange}
                render={item => item.title}
                styles={{
                    list: {
                        width: '100%',
                        height: 300,
                    }
                }}
            />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>
              Create Collection
            </Button>
          </Form.Item>
        </Form>
      </Card>

      <AddArtworkModal
        open={isModalVisible}
        onClose={() => setIsModalVisible(false)}
        onArtworkCreated={handleArtworkCreated}
      />
    </div>
    </ConfigProvider>
  );
};

export default CreateCollection;
