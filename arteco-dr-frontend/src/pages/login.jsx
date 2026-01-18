import React, { useState } from 'react';
import { Form, Input, Button, Card, Typography, message, ConfigProvider, Modal } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

const { Title, Text } = Typography;
// Make change to push build
const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [messageApi, contextHolder] = message.useMessage();
  
  // Reset Password State
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [resetForm] = Form.useForm();
  const [resetLoading, setResetLoading] = useState(false);

  const onFinish = async (values) => {
    setLoading(true);
    try {
      const response = await api.post('/Auth/login', values);
      
      if (response.data.token) {
        login(response.data.token);
        messageApi.success('Authentication Successful. Access Granted.');
        navigate('/');
      }
    } catch (error) {
      console.error('Login error:', error);
      if (!error.response) {
        messageApi.error('Network Error: Unable to connect to the server.');
      } else if (error.response.status === 401) {
        messageApi.error('Access Denied: Invalid Credentials.');
      } else {
        messageApi.error('System Error: Please check the API logs.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (values) => {
    setResetLoading(true);
    try {
      await api.post('/Auth/reset-password', values);
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
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', width: '100%', background: '#f0f2f5' }}>
        <Card style={{ width: 400, boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }}>
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            <Title level={3} style={{ color: '#246A73', margin: 0 }}>Arteco Condition Reporting</Title>
            <Text type="secondary">Admin Portal</Text>
          </div>
          
          <Form
            name="login"
            onFinish={onFinish}
            layout="vertical"
            size="large"
          >
            <Form.Item name="username" rules={[{ required: true, message: 'Identity required' }]}>
              <Input prefix={<UserOutlined />} placeholder="Username" />
            </Form.Item>
            <Form.Item name="password" rules={[{ required: true, message: 'Credential required' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="Password" />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading} block>
                Sign In
              </Button>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '15px' }}>
                <span style={{ color: '#246A73', cursor: 'pointer' }} onClick={() => setIsResetModalOpen(true)}>
                  Reset Password
                </span>
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
