import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ChevronLeft, Globe, Frame, User } from 'lucide-react';
import { Button, Modal, Upload, message, ConfigProvider } from 'antd';
import { UploadOutlined } from '@ant-design/icons';
import API_URL from './api';

function ArtistDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [artist, setArtist] = useState(null);
  const [loading, setLoading] = useState(true);
  const token = localStorage.getItem('token'); 
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [fileList, setFileList] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [messageApi, contextHolder] = message.useMessage();

  useEffect(() => {
    fetch(`${API_URL}/api/artists/${id}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
      .then(res => res.json())
      .then(data => {
        setArtist(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Fetch Error:", err);
        setLoading(false);
      });
  }, [id, token]);

  const handleUploadChange = ({ fileList: newFileList }) => setFileList(newFileList);

  const handleUploadImage = async () => {
    if (fileList.length === 0) return;
    setUploading(true);
    try {
      const formData = new FormData();
      fileList.forEach(file => {
        formData.append('files', file.originFileObj);
      });

      // Reuse the existing artwork upload endpoint which uploads to Azure and returns a URL
      const uploadRes = await fetch(`${API_URL}/api/artworks/upload-images`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      if (!uploadRes.ok) throw new Error('Upload failed');
      const uploadData = await uploadRes.json();
      const newImageUrl = uploadData.imageUrls[0];

      // Construct a clean payload matching ArtistUpdateDto
      const payload = {
        artistId: artist.artistId,
        firstName: artist.firstName,
        lastName: artist.lastName,
        pseudonym: artist.pseudonym,
        nationality: artist.nationality,
        birthYear: artist.birthYear,
        deathYear: artist.deathYear,
        biography: artist.biography,
        profileImageUrl: newImageUrl
      };

      // Update the artist record with the new image URL
      const updateRes = await fetch(`${API_URL}/api/artists/${id}`, {
        method: 'PUT',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!updateRes.ok) throw new Error('Failed to update artist record');

      messageApi.success('Artist image updated successfully');
      setIsUploadModalOpen(false);
      setFileList([]);
      
      // Update local state
      setArtist(prev => ({ ...prev, profileImageUrl: newImageUrl }));

    } catch (error) {
      console.error(error);
      messageApi.error('Failed to upload image');
    } finally {
      setUploading(false);
    }
  };

  if (loading) return <div style={{ textAlign: 'center', padding: '50px' }}>Loading Artist Profile...</div>;
  if (!artist) return <div style={{ textAlign: 'center', padding: '50px' }}>Artist record not found.</div>;

  return (
    <ConfigProvider theme={{ token: { colorPrimary: '#246A73' } }}>
    {contextHolder}
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '20px' }}>
      <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '5px' }}>
        <ChevronLeft size={20} /> Back to List
      </button>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '30px', marginBottom: '40px' }}>
        {/* Left Column: Image */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <div style={{ 
            backgroundColor: 'white', 
            borderRadius: '15px', 
            border: '1px solid #e2e8f0', 
            height: '300px', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            overflow: 'hidden'
          }}>
            {artist.profileImageUrl ? (
              <img src={artist.profileImageUrl} alt={`${artist.firstName} ${artist.lastName}`} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            ) : (
              <User size={80} color="#cbd5e1" />
            )}
          </div>
          <Button icon={<UploadOutlined />} onClick={() => setIsUploadModalOpen(true)} block>Update Artist Image</Button>
        </div>

        {/* Right Column: Details */}
        <div style={{ backgroundColor: 'white', borderRadius: '15px', padding: '40px', border: '1px solid #e2e8f0' }}>
          <h1 style={{ margin: '0 0 10px 0', color: '#1e293b' }}>{artist.firstName} {artist.lastName}</h1>
          <div style={{ display: 'flex', gap: '20px', color: '#64748b', marginBottom: '20px' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><Globe size={18} /> {artist.nationality}</span>
          </div>
          <p style={{ lineHeight: '1.8', color: '#475569', fontSize: '1.1rem' }}>{artist.biography}</p>
        </div>
      </div>

      <h2 style={{ marginBottom: '25px', color: '#1e293b', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <Frame size={24} /> Works in Collection
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '20px' }}>
        {artist.artworks?.map(work => (
          <Link to={`/artwork/${work.artworkId}`} key={work.artworkId} style={{ textDecoration: 'none' }}>
            <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '12px', border: '1px solid #edf2f7', boxShadow: '0 4px 6px rgba(0,0,0,0.02)' }}>
              <h4 style={{ margin: '0 0 5px 0', color: '#2c3e50' }}>{work.title}</h4>
              <p style={{ margin: '15px 0 0 0', fontWeight: 'bold', color: '#059669' }}>
                {/* FIX: Changed from appraisedValue to acquisitionCost */}
                £{work.acquisitionCost?.toLocaleString('en-GB') || '0.00'}
              </p>
            </div>
          </Link>
        ))}
      </div>

      <Modal
        title="Upload Artist Image"
        open={isUploadModalOpen}
        onCancel={() => setIsUploadModalOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setIsUploadModalOpen(false)}>Cancel</Button>,
          <Button key="submit" type="primary" loading={uploading} onClick={handleUploadImage} disabled={fileList.length === 0}>Upload</Button>
        ]}
      >
        <Upload.Dragger 
          name="files"
          multiple={false}
          fileList={fileList}
          beforeUpload={() => false}
          onChange={handleUploadChange}
          listType="picture"
          maxCount={1}
        >
          <p className="ant-upload-drag-icon"><UploadOutlined /></p>
          <p className="ant-upload-text">Click or drag file to this area to upload</p>
        </Upload.Dragger>
      </Modal>
    </div>
    </ConfigProvider>
  );
}

export default ArtistDetails;