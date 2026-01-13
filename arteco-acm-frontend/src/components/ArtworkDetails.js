import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Modal, Form, Input, InputNumber, Select, Checkbox, DatePicker, message, Button, ConfigProvider, Row, Col, Table, Upload, Carousel, Image } from 'antd';
import { UploadOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import { 
  ChevronLeft, 
  Palette, 
  Maximize, 
  BadgePoundSterling, 
  User,
  Calendar,
  ScrollText,
  Frame,
  Hash,
  Layers,
  Library,
  MapPin,
  Edit,
  AlertTriangle
} from 'lucide-react';
import API_URL from './api';

const { TextArea } = Input;
const { Option } = Select;

function ArtworkDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [artwork, setArtwork] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editForm] = Form.useForm();
  const [locations, setLocations] = useState([]);
  const [defectReports, setDefectReports] = useState([]);
  const [updating, setUpdating] = useState(false);
  const [messageApi, contextHolder] = message.useMessage();
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [fileList, setFileList] = useState([]);
  const [uploading, setUploading] = useState(false);
  const token = localStorage.getItem('token'); 

  const fetchArtwork = () => {
    if (!token) {
      navigate('/login');
      return;
    }
    setLoading(true);

    fetch(`${API_URL}/api/artworks/${id}`, {
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
      .then(res => {
        if (!res.ok) throw new Error('Asset retrieval failed');
        return res.json();
      })
      .then(data => {
        setArtwork(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Fetch Error:", err);
        setLoading(false);
      });
  };

  const fetchLocations = () => {
    fetch(`${API_URL}/api/locations`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(data => setLocations(data))
    .catch(err => console.error(err));
  };

  const fetchDefectReports = () => {
    fetch(`${API_URL}/api/DefectReports/artwork/${id}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => {
      if (!res.ok) {
        console.warn(`Defect reports fetch failed: ${res.status}`);
        return []; // Return empty array to prevent crash if endpoint is missing
      }
      return res.json();
    })
    .then(data => setDefectReports(data))
    .catch(err => console.error(err));
  };

  useEffect(() => {
    fetchArtwork();
    fetchLocations();
    fetchDefectReports();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, token, navigate]);

  const handleEditClick = () => {
    editForm.setFieldsValue({
      currentLocationId: artwork.currentLocationId || artwork.CurrentLocationId,
      medium: artwork.medium,
      heightCM: artwork.heightCM,
      widthCM: artwork.widthCM,
      depthCM: artwork.depthCM,
      frame: artwork.frame || artwork.Frame,
      lotNumber: artwork.lotNumber || artwork.LotNumber,
      acquisitionDate: (artwork.acquisitionDate || artwork.AcquisitionDate) ? dayjs(artwork.acquisitionDate || artwork.AcquisitionDate) : null,
      provenanceText: artwork.provenanceText || artwork.ProvenanceText
    });
    setIsEditModalOpen(true);
  };

  const handleUpdate = async (values) => {
    setUpdating(true);
    try {
      const payload = {
        ...artwork,
        ...values,
        acquisitionDate: values.acquisitionDate ? values.acquisitionDate.format('YYYY-MM-DD') : null
      };

      const response = await fetch(`${API_URL}/api/artworks/${id}`, {
        method: 'PUT',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        messageApi.success('Artwork details updated successfully');
        setIsEditModalOpen(false);
        fetchArtwork(); // Refresh data
      } else {
        messageApi.error('Failed to update artwork details');
      }
    } catch (error) {
      console.error('Update Error:', error);
      messageApi.error('System error occurred during update');
    } finally {
      setUpdating(false);
    }
  };

  const handleUploadChange = ({ fileList: newFileList }) => setFileList(newFileList);

  const handleUploadImages = async () => {
    if (fileList.length === 0) return;
    setUploading(true);
    try {
      const formData = new FormData();
      fileList.forEach(file => {
        formData.append('files', file.originFileObj);
      });

      const uploadRes = await fetch(`${API_URL}/api/artworks/upload-images`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      if (!uploadRes.ok) throw new Error('Upload failed');
      const uploadData = await uploadRes.json();
      
      const linkRes = await fetch(`${API_URL}/api/artworks/${id}/images`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(uploadData.imageUrls)
      });

      if (!linkRes.ok) throw new Error('Linking images failed');

      messageApi.success('Images uploaded successfully');
      setIsUploadModalOpen(false);
      setFileList([]);
      fetchArtwork();
    } catch (error) {
      console.error(error);
      messageApi.error('Failed to upload images');
    } finally {
      setUploading(false);
    }
  };

  if (loading) return <div style={{ textAlign: 'center', padding: '50px' }}>Loading Asset Record...</div>;
  if (!artwork) return <div style={{ textAlign: 'center', padding: '50px' }}>Asset not found.</div>;

  const edition = artwork.edition || artwork.Edition;

  const defectColumns = [
    { title: 'Date', dataIndex: 'createdDate', key: 'createdDate', render: (text) => dayjs(text).format('DD/MM/YYYY HH:mm') },
    { title: 'Reported By', dataIndex: 'createdBy', key: 'createdBy' },
    { title: 'Report Link', dataIndex: 'reportUrl', key: 'reportUrl', render: (text) => <a href={text} target="_blank" rel="noopener noreferrer">View Report</a> },
  ];

  return (
    <ConfigProvider theme={{ token: { colorPrimary: '#246A73' } }}>
    {contextHolder}
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      {/* FIXED: Dynamic Back Button */}
      <button 
        onClick={() => navigate(-1)} 
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
        <ChevronLeft size={20} /> Back to List
      </button>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '40px', backgroundColor: 'white', padding: '30px', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)', alignItems: 'start' }}>
        {/* Left: Image Placeholder */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '15px', minWidth: 0 }}>
          <div style={{ backgroundColor: '#f1f5f9', borderRadius: '12px', overflow: 'hidden', height: '400px', position: 'relative' }}>
            {artwork.artworkImages && artwork.artworkImages.length > 0 ? (
              <Carousel arrows style={{ width: '100%', height: '100%' }}>
                {artwork.artworkImages.map((img, idx) => (
                  <div key={idx}>
                    <div style={{ height: '400px', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#f1f5f9' }}>
                      <Image 
                        src={img.blobUrl} 
                        alt={artwork.title} 
                        fallback="https://placehold.co/400x400/png?text=Image+Unavailable"
                        style={{ maxHeight: '400px', maxWidth: '100%', objectFit: 'contain' }} 
                      />
                    </div>
                  </div>
                ))}
              </Carousel>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '400px', backgroundColor: '#f1f5f9' }}>
                <img src="https://placehold.co/400x400/png?text=No+Image+Available" alt="Artwork unavailable" style={{ maxHeight: '100%', maxWidth: '100%', objectFit: 'contain' }} />
              </div>
            )}
          </div>
          <Button icon={<UploadOutlined />} onClick={() => setIsUploadModalOpen(true)} block>Update Artwork Images</Button>
        </div>

        {/* Right: Details */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ color: '#3b82f6', fontWeight: 'bold', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                Artwork Record #{artwork.artworkId}
              </span>
              <h1 style={{ margin: '10px 0 20px 0', color: '#1e293b', fontSize: '2.25rem' }}>{artwork.title}</h1>
            </div>
            <button 
              onClick={handleEditClick}
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '8px', 
                backgroundColor: '#246A73', 
                border: 'none', 
                borderRadius: '8px', 
                padding: '8px 16px', 
                cursor: 'pointer', 
                color: 'white', 
                fontWeight: '600'
              }}
            >
              <Edit size={18} /> Edit Details
            </button>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginBottom: '30px' }}>
            {artwork.artistId && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
                <User size={20} /> 
                <span>
                  <strong>Artist:</strong>{' '}
                  <span 
                    onClick={() => navigate(`/artist/${artwork.artistId}`)}
                    style={{ color: '#3b82f6', cursor: 'pointer', fontWeight: '600', textDecoration: 'underline' }}
                  >
                    {artwork.artistName || 'View Artist Profile'}
                  </span>
                </span>
              </div>
            )}
            {(artwork.collections || artwork.Collections) && (artwork.collections || artwork.Collections).length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
                <Library size={20} /> 
                <span><strong>Collection:</strong> {(artwork.collections || artwork.Collections).join(', ')}</span>
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <MapPin size={20} /> 
              <span><strong>Location:</strong> {artwork.locationName || artwork.LocationName || 'Not Assigned'}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Palette size={20} /> <span><strong>Medium:</strong> {artwork.medium}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Maximize size={20} /> <span><strong>Dimensions:</strong> {artwork.heightCM} x {artwork.widthCM} cm</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Frame size={20} /> <span><strong>Framed:</strong> {(artwork.frame || artwork.Frame) ? 'Yes' : 'No'}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Hash size={20} /> <span><strong>Lot Number:</strong> {artwork.lotNumber || artwork.LotNumber || 'N/A'}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Calendar size={20} /> <span><strong>Created:</strong> {artwork.creationDateDisplay || artwork.CreationDateDisplay || 'N/A'}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#475569' }}>
              <Calendar size={20} /> <span><strong>Acquired:</strong> {(artwork.acquisitionDate || artwork.AcquisitionDate) ? new Date(artwork.acquisitionDate || artwork.AcquisitionDate).toLocaleDateString('en-GB') : 'N/A'}</span>
            </div>
          </div>
        </div>

        {edition && (
          <div style={{ gridColumn: '1 / -1', padding: '20px', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
            <h4 style={{ margin: '0 0 15px 0', color: '#475569', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1rem' }}>
              <Layers size={18} /> Edition Details
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px', fontSize: '0.9rem', color: '#334155' }}>
              <div><strong>Type:</strong> {edition.editionType || edition.EditionType || 'N/A'}</div>
              <div><strong>Marking:</strong> {edition.marking || edition.Marking || 'N/A'}</div>
              <div><strong>Rarity:</strong> {edition.rarity || edition.Rarity || 'N/A'}</div>
              <div><strong>Est. Value:</strong> {edition.estimatedValueRelative || edition.EstimatedValueRelative || 'N/A'}</div>
            </div>
          </div>
        )}

        <div style={{ gridColumn: '1 / -1', padding: '20px', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <p style={{ margin: 0, color: '#64748b', fontSize: '0.8rem', fontWeight: 'bold', textTransform: 'uppercase' }}>Current Valuation</p>
              <p style={{ margin: 0, fontSize: '1.75rem', fontWeight: 'bold', color: '#059669' }}>
                £{artwork.acquisitionCost?.toLocaleString('en-GB')}
              </p>
            </div>
            <button 
              onClick={() => navigate(`/add-appraisal/${artwork.artworkId}`)}
              style={{ 
                backgroundColor: '#246A73', 
                color: 'white', 
                border: 'none', 
                padding: '10px 20px', 
                borderRadius: '8px', 
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontWeight: '600'
              }}
            >
              <BadgePoundSterling size={18} /> Update Valuation
            </button>
          </div>
        </div>

        {/* Full Width Section: Provenance & Status */}
        <div style={{ gridColumn: '1 / -1', marginTop: '10px', borderTop: '1px solid #f1f5f9', paddingTop: '30px' }}>
          <h4 style={{ margin: '0 0 15px 0', color: '#475569', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.1rem' }}>
            <ScrollText size={20} /> Provenance History
          </h4>
          <p style={{ margin: '0 0 30px 0', color: '#64748b', fontSize: '0.95rem', lineHeight: '1.7', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {artwork.provenanceText || artwork.ProvenanceText || artwork.provenance || artwork.Provenance || 'No provenance history recorded.'}
          </p>

          <div style={{ backgroundColor: '#f8fafc', padding: '15px', borderRadius: '8px', display: 'inline-block' }}>
             <p style={{ margin: 0, color: '#475569', fontSize: '0.9rem' }}>
               <strong>Current Status:</strong> <span style={{ color: '#059669', fontWeight: '600' }}>{artwork.status || 'Managed Asset'}</span>
             </p>
           </div>
        </div> 

        {/* Full Width Section: Defect Reports */}
        <div style={{ gridColumn: '1 / -1', marginTop: '10px', borderTop: '1px solid #f1f5f9', paddingTop: '30px' }}>
          <h4 style={{ margin: '0 0 15px 0', color: '#475569', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.1rem' }}>
            <AlertTriangle size={20} /> Condition Reports
          </h4>
          <Table 
            dataSource={defectReports} 
            columns={defectColumns} 
            rowKey="defectReportId" 
            pagination={false} 
          />
        </div>
      </div>
    </div>

    <Modal
      title="Edit Artwork Details"
      open={isEditModalOpen}
      onCancel={() => setIsEditModalOpen(false)}
      footer={[
        <Button key="cancel" onClick={() => setIsEditModalOpen(false)}>Cancel</Button>,
        <Button key="submit" type="primary" loading={updating} onClick={() => editForm.submit()}>Save Changes</Button>
      ]}
      width={700}
    >
      <Form form={editForm} layout="vertical" onFinish={handleUpdate}>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item name="currentLocationId" label="Location">
              <Select placeholder="Select Location" allowClear>
                {locations.map(loc => (
                  <Option key={loc.locationId} value={loc.locationId}>{loc.locationName}</Option>
                ))}
              </Select>
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item name="medium" label="Medium">
              <Input />
            </Form.Item>
          </Col>
        </Row>
        <Row gutter={16}>
          <Col span={8}><Form.Item name="heightCM" label="Height (cm)"><InputNumber style={{ width: '100%' }} /></Form.Item></Col>
          <Col span={8}><Form.Item name="widthCM" label="Width (cm)"><InputNumber style={{ width: '100%' }} /></Form.Item></Col>
          <Col span={8}><Form.Item name="depthCM" label="Depth (cm)"><InputNumber style={{ width: '100%' }} /></Form.Item></Col>
        </Row>
        <Row gutter={16}>
          <Col span={8}>
            <Form.Item name="frame" valuePropName="checked" label=" "><Checkbox>Framed</Checkbox></Form.Item>
          </Col>
          <Col span={8}>
            <Form.Item name="lotNumber" label="Lot Number"><Input /></Form.Item>
          </Col>
          <Col span={8}>
            <Form.Item name="acquisitionDate" label="Acquired Date">
              <DatePicker style={{ width: '100%' }} format="DD/MM/YYYY" />
            </Form.Item>
          </Col>
        </Row>
        <Form.Item name="provenanceText" label="Provenance History">
          <TextArea rows={4} />
        </Form.Item>
      </Form>
    </Modal>

    <Modal
      title="Upload Artwork Images"
      open={isUploadModalOpen}
      onCancel={() => setIsUploadModalOpen(false)}
      footer={[
        <Button key="cancel" onClick={() => setIsUploadModalOpen(false)}>Cancel</Button>,
        <Button key="submit" type="primary" loading={uploading} onClick={handleUploadImages} disabled={fileList.length === 0}>Upload</Button>
      ]}
    >
      <Upload.Dragger 
        name="files"
        multiple={true}
        fileList={fileList}
        beforeUpload={() => false}
        onChange={handleUploadChange}
        listType="picture"
      >
        <p className="ant-upload-drag-icon"><UploadOutlined /></p>
        <p className="ant-upload-text">Click or drag files to this area to upload</p>
      </Upload.Dragger>
    </Modal>
    </ConfigProvider>
  );
}

export default ArtworkDetails;