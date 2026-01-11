import React, { useState } from 'react';
import { Form, Input, Button, Card, Typography, message, ConfigProvider, Modal } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import API_URL from './api';


const { Title } = Typography;

const Login = () => {
  const [messageApi, contextHolder] = message.useMessage();
  const [loading, setLoading] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [resetForm] = Form.useForm();
  const [resetLoading, setResetLoading] = useState(false);
  const navigate = useNavigate();

  const onFinish = async (values) => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/auth/login`, values);
      if (response.data.token) {
        localStorage.setItem('token', response.data.token);
        messageApi.success('Authentication Successful. Access Granted.');
        navigate('/');
      }
    } catch (error) {
      if (!error.response) {
        messageApi.error('Network Error: Unable to connect to the server. Is the API running?');
      } else if (error.response.status === 500) {
        messageApi.error('System Error: Please check the API logs.');
      } else {
        messageApi.error('Access Denied: Invalid Credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (values) => {
    setResetLoading(true);
    try {
      await axios.post(`${API_URL}/api/auth/reset-password`, values);
      messageApi.success('Password updated successfully. Please login with your new password.');
      setIsResetModalOpen(false);
      resetForm.resetFields();
    } catch (error) {
      messageApi.error(error.response?.data?.message || 'Failed to reset password.');
    } finally {
      setResetLoading(false);
    }
  };

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
    {contextHolder}
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f0f2f5' }}>
      <Card style={{ width: 400, boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <Title level={3}>ARTECO Collection Manager</Title>
          <Typography.Text type="secondary">Fine Art Portal</Typography.Text>
        </div>
        
        <Form name="login_form" onFinish={onFinish} layout="vertical" size="large">
          <Form.Item name="username" rules={[{ required: true, message: 'Identity required' }]}>
            <Input 
              prefix={<UserOutlined />} 
              placeholder="Username" 
              autoComplete="username" 
            />
          </Form.Item>

          <Form.Item name="password" rules={[{ required: true, message: 'Credential required' }]}>
            <Input.Password 
              prefix={<LockOutlined />} 
              placeholder="Password" 
              autoComplete="current-password" 
            />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={loading}>
              Sign In
            </Button>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '15px' }}>
              <Link to="/register">Register as a New User</Link>
              <span style={{ color: '#246A73', cursor: 'pointer' }} onClick={() => setIsResetModalOpen(true)}>Reset your Password</span>
            </div>
          </Form.Item>
        </Form>
      </Card>

      <Modal
        title="Reset Password"
        open={isResetModalOpen}
        onCancel={() => setIsResetModalOpen(false)}
        footer={null}
      >
        <Form form={resetForm} onFinish={handleResetPassword} layout="vertical">
          <Form.Item name="username" label="Username" rules={[{ required: true, message: 'Please enter your username' }]}>
            <Input prefix={<UserOutlined />} placeholder="Username" />
          </Form.Item>
          <Form.Item name="oldPassword" label="Current Password" rules={[{ required: true, message: 'Please enter your current password' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="Current Password" />
          </Form.Item>
          <Form.Item name="newPassword" label="New Password" rules={[{ required: true, message: 'Please enter a new password' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="New Password" />
          </Form.Item>
          <Form.Item 
            name="confirmPassword" 
            label="Confirm New Password" 
            dependencies={['newPassword']}
            rules={[
              { required: true, message: 'Please confirm your new password' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('newPassword') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('The two passwords that you entered do not match!'));
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Confirm New Password" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={resetLoading}>
              Update Password
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
    </ConfigProvider>
  );
};

export default Login;