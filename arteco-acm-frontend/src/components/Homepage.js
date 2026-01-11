import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  FolderOutlined, 
  PictureOutlined, 
  UserOutlined, 
  FileProtectOutlined
} from '@ant-design/icons';
import './Homepage.css';

const Homepage = () => {
  const navigate = useNavigate();

  const menuOptions = [
    {
      title: 'Collections',
      icon: <FolderOutlined />,
      path: '/collections',
      description: 'Manage your private galleries.'
    },
    {
      title: 'Artwork',
      icon: <PictureOutlined />,
      path: '/artworks',
      description: 'View and edit your artworks.'
    },
    {
      title: 'Artists',
      icon: <UserOutlined />,
      path: '/artists',
      description: 'Maintain biographical records and information.'
    },
    {
      title: 'Appraisals',
      icon: <FileProtectOutlined />,
      path: '/appraisals',
      description: 'Review valuations and insurance records.'
    }
  ];

  return (
    <div className="dashboard-content">
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ margin: 0, color: '#1e293b', fontSize: '1.875rem' }}>Arteco Collection Management</h1>
        <p style={{ color: '#64748b', marginTop: '8px' }}>Select a module to manage your collections.</p>
      </div>
      
      <div className="options-grid">
        {menuOptions.map((option) => (
          <div 
            key={option.title} 
            className="option-card" 
            onClick={() => navigate(option.path)}
          >
            <div className="option-icon">{option.icon}</div>
            <h2>{option.title}</h2>
            <p>{option.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Homepage;