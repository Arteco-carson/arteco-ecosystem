import React, { useEffect, useState } from 'react';
import { Table, Card, Button, Space, Typography, Layout, message } from 'antd';
import { FilePdfOutlined, ReloadOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

const { Header, Content } = Layout;
const { Title } = Typography;

const ReportList = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setLoading(true);
    try {
      // Calling search without parameters returns all reports accessible to the user.
      // The backend automatically filters this:
      // - Customers see only reports for their artworks.
      // - Employees see all reports.
      const response = await api.get('/DefectReports/search');
      setReports(response.data);
    } catch (error) {
      console.error('Error fetching reports:', error);
      message.error('Failed to load reports.');
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'defectReportId',
      key: 'defectReportId',
      width: 80,
      sorter: (a, b) => a.defectReportId - b.defectReportId,
    },
    {
      title: 'Report Name',
      dataIndex: 'reportName',
      key: 'reportName',
      sorter: (a, b) => (a.reportName || '').localeCompare(b.reportName || ''),
    },
    {
      title: 'Artwork',
      dataIndex: 'artworkTitle',
      key: 'artworkTitle',
      sorter: (a, b) => (a.artworkTitle || '').localeCompare(b.artworkTitle || ''),
    },
    {
      title: 'Date Created',
      dataIndex: 'createdDate',
      key: 'createdDate',
      render: (text) => new Date(text).toLocaleDateString(),
      sorter: (a, b) => new Date(a.createdDate) - new Date(b.createdDate),
      defaultSortOrder: 'descend',
    },
    {
      title: 'Actions',
      key: 'action',
      render: (_, record) => (
        <Space size="middle">
          <Button 
            type="link" 
            icon={<FilePdfOutlined />} 
            href={record.reportUrl} 
            target="_blank"
            disabled={!record.reportUrl}
          >
            View PDF
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', background: '#246A73', padding: '0 24px' }}>
        <Button 
            type="text" 
            icon={<ArrowLeftOutlined />} 
            onClick={() => navigate('/')} 
            style={{ color: '#fff', marginRight: '16px' }}
        >
            Back
        </Button>
        <Title level={4} style={{ color: '#fff', margin: 0 }}>Condition Reports Archive</Title>
      </Header>
      <Content style={{ padding: '24px 50px', background: '#f0f2f5' }}>
        <div style={{ width: '100%' }}>
            <Card 
            title="All Reports" 
            extra={<Button icon={<ReloadOutlined />} onClick={fetchReports}>Refresh</Button>}
            >
            <Table 
                columns={columns} 
                dataSource={reports} 
                rowKey="defectReportId" 
                loading={loading}
                pagination={{ pageSize: 10 }}
            />
            </Card>
        </div>
      </Content>
    </Layout>
  );
};

export default ReportList;