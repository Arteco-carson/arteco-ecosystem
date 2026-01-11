import React from 'react';
import { Layout, Button, Typography, Card, Row, Col } from 'antd';
import { LogoutOutlined, FileTextOutlined, SettingOutlined, SearchOutlined } from '@ant-design/icons';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

const { Header, Content } = Layout;
const { Title, Text } = Typography;

const Dashboard = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const menuOptions = [
    {
      title: 'Recent Reports',
      icon: <FileTextOutlined style={{ fontSize: '24px', color: '#246A73' }} />,
      description: 'View and manage recently created condition reports.',
      path: '/reports'
    },
    {
      title: 'Report Templates',
      icon: <SettingOutlined style={{ fontSize: '24px', color: '#246A73' }} />,
      description: 'Configure templates for condition reporting.',
      path: '/templates'
    },
    {
      title: 'Search Reports',
      icon: <SearchOutlined style={{ fontSize: '24px', color: '#246A73' }} />,
      description: 'Search the archive for specific reports.',
      path: '/search'
    }
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#246A73', padding: '0 24px' }}>
        <Title level={4} style={{ color: '#fff', margin: 0 }}>Arteco Condition Reporting</Title>
        <Button type="text" icon={<LogoutOutlined />} onClick={logout} style={{ color: '#fff' }}>Logout</Button>
      </Header>
      <Content style={{ padding: '40px 50px', background: '#f0f2f5' }}>
        <div style={{ width: '100%' }}>
          <div style={{ marginBottom: '32px' }}>
            <Title level={2} style={{ margin: 0, color: '#1e293b' }}>Dashboard</Title>
            <Text type="secondary">Select a module to manage condition reports.</Text>
          </div>
          
          <Row gutter={[24, 24]}>
            {menuOptions.map((option) => (
              <Col xs={24} sm={12} md={8} key={option.title}>
                <Card 
                  hoverable 
                  style={{ height: '100%', borderRadius: '12px' }}
                  onClick={() => navigate(option.path)}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '20px 0' }}>
                    <div style={{ background: '#f0fdf4', padding: '16px', borderRadius: '50%', marginBottom: '16px' }}>
                      {option.icon}
                    </div>
                    <Title level={4} style={{ marginBottom: '8px' }}>{option.title}</Title>
                    <Text type="secondary">{option.description}</Text>
                  </div>
                </Card>
              </Col>
            ))}
          </Row>
        </div>
      </Content>
    </Layout>
  );
};

export default Dashboard;
