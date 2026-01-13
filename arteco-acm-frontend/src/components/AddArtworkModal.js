import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Form, Input, Button, message, Modal, InputNumber, Space, Upload, Select, Checkbox, Divider, Row, Col } from 'antd';
import { PlusOutlined, UploadOutlined } from '@ant-design/icons';
import AddArtistModal from './AddArtistModal';
import API_URL from './api';

const { TextArea } = Input;
const { Option } = Select;

const AddArtworkModal = ({ open, onClose, onArtworkCreated }) => {
  const [artworkForm] = Form.useForm();
  const [artists, setArtists] = useState([]);
  const [editions, setEditions] = useState([]);
  const [locations, setLocations] = useState([]);
  const [modalLoading, setModalLoading] = useState(false);
  const [isArtistModalVisible, setIsArtistModalVisible] = useState(false);
  const [fileList, setFileList] = useState([]);
  const navigate = useNavigate();

  const handleUploadChange = ({ fileList: newFileList }) => {
    setFileList(newFileList);
  };

  const beforeUpload = (file) => {
    // Prevent auto-upload
    return false;
  };

  const getAuthHeader = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) return null;
    return { Authorization: `Bearer ${token.trim()}` };
  }, []);

  const fetchArtists = useCallback(async () => {
    if (open) {
      try {
        const headers = getAuthHeader();
        if (!headers) return;
        const res = await axios.get(`${API_URL}/api/artists`, { headers });
        setArtists(res.data);
      } catch (error) {
        console.error('Failed to fetch artists:', error);
        message.error('Could not load artists.');
      }
    }
  }, [open, getAuthHeader]);

  const fetchEditions = useCallback(async () => {
    if (open) {
      try {
        const headers = getAuthHeader();
        if (!headers) return;
        const res = await axios.get(`${API_URL}/api/artworks/editions`, { headers });
        console.log("Editions loaded:", res.data);
        setEditions(res.data);
      } catch (error) {
        if (error.response) {
             console.error('Failed to fetch editions:', error.response.status, error.response.data);
        } else {
             console.error('Failed to fetch editions:', error.message);
        }
      }
    }
  }, [open, getAuthHeader]);

  const fetchLocations = useCallback(async () => {
    if (open) {
      try {
        const headers = getAuthHeader();
        if (!headers) return;
        const res = await axios.get(`${API_URL}/api/locations`, { headers });
        setLocations(res.data);
      } catch (error) {
        console.error('Failed to fetch locations:', error);
      }
    }
  }, [open, getAuthHeader]);

  useEffect(() => {
    fetchArtists();
    fetchEditions();
    fetchLocations();
  }, [fetchArtists, fetchEditions, fetchLocations]);

  const handleCreateArtwork = async (values) => {
    setModalLoading(true);
    try {
      const headers = getAuthHeader();
      if (!headers) {
        message.error('Authentication token not found. Please log in again.');
        navigate('/login');
        return;
      }

      let imageUrls = [];
      if (fileList.length > 0) {
        const formData = new FormData();
        fileList.forEach(file => {
          formData.append('files', file.originFileObj);
        });

        const uploadRes = await axios.post(`${API_URL}/api/artworks/upload-images`, formData, {
          headers: {
            ...headers,
            'Content-Type': 'multipart/form-data',
          },
        });
        imageUrls = uploadRes.data.imageUrls;
      }

      const payload = { ...values, imageUrls };
      const res = await axios.post(`${API_URL}/api/artworks`, payload, { headers });
      
      message.success(`Artwork "${res.data.title}" created successfully.`);
      
      if (onArtworkCreated) {
        onArtworkCreated(res.data);
      }
      
      artworkForm.resetFields();
      setFileList([]);
      onClose();
    } catch (error) {
      console.error('Failed to create artwork:', error);
      message.error('Failed to create new artwork. Please try again.');
    } finally {
      setModalLoading(false);
    }
  };

  const handleArtistCreated = (newArtist) => {
    setArtists(prev => [...prev, newArtist]);
    artworkForm.setFieldsValue({ artistId: newArtist.artistId });
    fetchArtists();
  };

  return (
    <>
      <Modal
        title="Create New Artwork"
        open={open}
        onCancel={onClose}
        footer={[
          <Button key="back" onClick={onClose}>
            Cancel
          </Button>,
          <Button key="submit" type="primary" loading={modalLoading} onClick={() => artworkForm.submit()}>
            Create
          </Button>,
        ]}
      >
        <Form form={artworkForm} layout="vertical" onFinish={handleCreateArtwork}>
            <Form.Item name="title" label="Title" rules={[{ required: true }]}>
                <Input />
            </Form.Item>
            <Form.Item label="Artist" required>
                <Space.Compact style={{ width: '100%' }}>
                    <Form.Item
                        name="artistId"
                        noStyle
                        rules={[{ required: true, message: 'Please select an artist' }]}
                    >
                        <Select placeholder="Select an artist" showSearch filterOption={(input, option) =>
                            option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
                        }>
                            {artists.map(artist => (
                                <Option key={artist.artistId} value={artist.artistId}>
                                    {`${artist.firstName} ${artist.lastName}`}
                                </Option>
                            ))}
                        </Select>
                    </Form.Item>
                    <Button icon={<PlusOutlined />} onClick={() => setIsArtistModalVisible(true)}>
                        Add New Artist
                    </Button>
                </Space.Compact>
            </Form.Item>
            <Form.Item name="medium" label="Medium">
                <Input />
            </Form.Item>
            <Form.Item name="currentLocationId" label="Location">
                <Select placeholder="Select Location" allowClear>
                    {locations.map(loc => (
                        <Option key={loc.locationId} value={loc.locationId}>
                            {loc.locationName}
                        </Option>
                    ))}
                </Select>
            </Form.Item>
            <Space style={{ display: 'flex', marginBottom: 8 }} align="baseline">
                <Form.Item name="frame" valuePropName="checked">
                    <Checkbox>Framed?</Checkbox>
                </Form.Item>
                <Form.Item name="lotNumber" label="Lot Number" style={{ marginLeft: 20 }}>
                    <Input placeholder="e.g. Lot 452" />
                </Form.Item>
            </Space>
            <Space>
                <Form.Item name="heightCM" label="Height (cm)">
                    <InputNumber min={0} />
                </Form.Item>
                <Form.Item name="widthCM" label="Width (cm)">
                    <InputNumber min={0} />
                </Form.Item>
                <Form.Item name="depthCM" label="Depth (cm)">
                    <InputNumber min={0} />
                </Form.Item>
            </Space>
            <Form.Item name="weightKG" label="Weight (kg)">
                <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="creationDateDisplay" label="Creation Date">
                <Input placeholder="e.g., 'ca. 1920' or '2023'" />
            </Form.Item>
            
            <Divider orientation="left" style={{ fontSize: '0.9rem', color: '#64748b' }}>Edition Details (Optional)</Divider>
            <Row gutter={16}>
                <Col span={24}>
                    <Form.Item name="editionId" label="Edition Type">
                        <Select placeholder="Select Edition Type" allowClear>
                            {editions.map(edition => (
                                <Option key={edition.editionId || edition.EditionId} value={edition.editionId || edition.EditionId}>
                                    {edition.editionType || edition.EditionType} — {edition.marking || edition.Marking} ({edition.rarity || edition.Rarity})
                                </Option>
                            ))}
                        </Select>
                    </Form.Item>
                </Col>
            </Row>
            <Divider />

            <Form.Item name="provenanceText" label="Provenance">
                <TextArea rows={3} />
            </Form.Item>
            <Form.Item label="Artwork Images">
                <Upload.Dragger 
                    name="files"
                    multiple={true}
                    fileList={fileList}
                    beforeUpload={beforeUpload}
                    onChange={handleUploadChange}
                    listType="picture"
                >
                    <p className="ant-upload-drag-icon">
                        <UploadOutlined />
                    </p>
                    <p className="ant-upload-text">Click or drag files to this area to upload</p>
                    <p className="ant-upload-hint">Support for a single or bulk upload.</p>
                </Upload.Dragger>
            </Form.Item>
            <Form.Item name="acquisitionCost" label="Acquisition Cost (£)">
                <InputNumber min={0} style={{ width: '100%' }} formatter={value => `£ ${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')} parser={value => value.replace(/£\s?|(,*)/g, '')} />
            </Form.Item>
        </Form>
      </Modal>

      <AddArtistModal
        visible={isArtistModalVisible}
        onClose={() => setIsArtistModalVisible(false)}
        onArtistCreated={handleArtistCreated}
      />
    </>
  );
};

export default AddArtworkModal;
