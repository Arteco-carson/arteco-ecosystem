import React, { useState, useEffect, useCallback } from 'react';
import { Card, Descriptions, Button, Tag, Spin, ConfigProvider, Modal, Form, Input, message, Select, Checkbox } from 'antd';
import { useNavigate } from 'react-router-dom';
import API_URL from './api';

const Profile = () => {
  const navigate = useNavigate();
  const [messageApi, contextHolder] = message.useMessage();
  const [fetching, setFetching] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [updateLoading, setUpdateLoading] = useState(false);
  const [user, setUser] = useState({
    firstName: '', lastName: '', emailAddress: '', username: '',
    userRole: '', location: 'United Kingdom', currency: 'GBP', telephoneNumber: ''
  });
  const [locations, setLocations] = useState([]);
  const [roles, setRoles] = useState([]);
  const [currencies, setCurrencies] = useState([]);
  const [form] = Form.useForm();
  const [locationForm] = Form.useForm();
  const [isLocationModalOpen, setIsLocationModalOpen] = useState(false);
  const [locationLoading, setLocationLoading] = useState(false);
  const [editLocationForm] = Form.useForm();
  const [isEditLocationModalOpen, setIsEditLocationModalOpen] = useState(false);
  const [selectedLocation, setSelectedLocation] = useState(null);
  const [editLocationLoading, setEditLocationLoading] = useState(false);

  const fetchProfile = useCallback(async () => {
    const token = localStorage.getItem('token');
    if (!token) return navigate('/login');

    try {
      const response = await fetch(`${API_URL}/api/user/profile`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
      });
      const data = await response.json();
      setUser(prev => ({ ...prev, ...data }));

      const locResponse = await fetch(`${API_URL}/api/locations`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
      });
      if (locResponse.ok) {
        const locData = await locResponse.json();
        setLocations(locData);
      }

      const roleResponse = await fetch(`${API_URL}/api/userroles`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
      });
      if (roleResponse.ok) {
        const roleData = await roleResponse.json();
        setRoles(roleData);
      }

      const currencyResponse = await fetch(`${API_URL}/api/user/currencies`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
      });
      if (currencyResponse.ok) {
        const currencyData = await currencyResponse.json();
        setCurrencies(currencyData);
      }
    } finally {
      setFetching(false);
    }
  }, [navigate]);

  useEffect(() => { fetchProfile(); }, [fetchProfile]);

  const handleEditClick = () => {
    form.setFieldsValue({
      firstName: user.firstName,
      lastName: user.lastName,
      emailAddress: user.emailAddress || user.EmailAddress || user.email,
      telephoneNumber: user.telephoneNumber,
      roleId: user.roleId,
      currencyCode: user.currencyCode
    });
    setIsModalOpen(true);
  };

  const handleUpdateProfile = async (values) => {
    setUpdateLoading(true);
    const token = localStorage.getItem('token');
    try {
      const response = await fetch(`${API_URL}/api/user/profile`, {
        method: 'PUT',
        headers: { 
          'Authorization': `Bearer ${token}`, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify(values)
      });

      if (response.ok) {
        messageApi.success('Profile updated successfully.');
        setIsModalOpen(false);
        fetchProfile();
      } else {
        messageApi.error('Failed to update profile.');
      }
    } catch (error) {
      console.error(error);
      messageApi.error('System error occurred.');
    } finally {
      setUpdateLoading(false);
    }
  };

  const handleAddLocation = async (values) => {
    setLocationLoading(true);
    const token = localStorage.getItem('token');
    try {
      const response = await fetch(`${API_URL}/api/locations`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify(values)
      });

      if (response.ok) {
        messageApi.success('Location added successfully.');
        setIsLocationModalOpen(false);
        locationForm.resetFields();
        fetchProfile();
      } else {
        messageApi.error('Failed to add location.');
      }
    } catch (error) {
      console.error(error);
      messageApi.error('System error occurred.');
    } finally {
      setLocationLoading(false);
    }
  };

  const handleLocationClick = (loc) => {
    setSelectedLocation(loc);
    editLocationForm.setFieldsValue({
      locationName: loc.locationName,
      addressLine1: loc.addressLine1,
      city: loc.city,
      postcode: loc.postcode,
      country: loc.country,
      isDefault: loc.isDefault
    });
    setIsEditLocationModalOpen(true);
  };

  const handleUpdateLocation = async (values) => {
    setEditLocationLoading(true);
    const token = localStorage.getItem('token');
    try {
      const response = await fetch(`${API_URL}/api/locations/${selectedLocation.locationId}`, {
        method: 'PUT',
        headers: { 
          'Authorization': `Bearer ${token}`, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify({ ...selectedLocation, ...values })
      });

      if (response.ok) {
        messageApi.success('Location updated successfully.');
        setIsEditLocationModalOpen(false);
        fetchProfile();
      } else {
        messageApi.error('Failed to update location.');
      }
    } catch (error) {
      console.error(error);
      messageApi.error('System error occurred.');
    } finally {
      setEditLocationLoading(false);
    }
  };

  const handleDeleteLocation = () => {
    Modal.confirm({
      title: 'Delete Location',
      content: 'Are you sure you want to delete this location? This action cannot be undone.',
      okText: 'Delete',
      okType: 'danger',
      cancelText: 'Cancel',
      onOk: async () => {
        setEditLocationLoading(true);
        const token = localStorage.getItem('token');
        try {
          const response = await fetch(`${API_URL}/api/locations/${selectedLocation.locationId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
          });

          if (response.ok) {
            messageApi.success('Location deleted successfully.');
            setIsEditLocationModalOpen(false);
            fetchProfile();
          } else {
            messageApi.error('Failed to delete location.');
          }
        } catch (error) {
          console.error(error);
          messageApi.error('System error occurred.');
        } finally {
          setEditLocationLoading(false);
        }
      }
    });
  };

  if (fetching) return <Spin size="large" tip="Validating Credentials..." />;

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#246A73',
        },
      }}
    >
      {contextHolder}
      <Card title="UserProfile" extra={
        <div style={{ display: 'flex', gap: '10px' }}>
          {user.userRole === 'Administrator' && (
            <Button onClick={() => navigate('/audit-logs')}>System Logs</Button>
          )}
          <Button type="primary" onClick={() => setIsLocationModalOpen(true)}>Add Location</Button>
          <Button type="primary" onClick={handleEditClick}>Edit Profile</Button>
        </div>
      }>
        <Descriptions bordered column={1} title="Identity Details">
          <Descriptions.Item label="Full Name">{user.firstName} {user.lastName}</Descriptions.Item>
          <Descriptions.Item label="Email Address">{user.emailAddress || user.EmailAddress || user.email}</Descriptions.Item>
          <Descriptions.Item label="Contact Number">{user.telephoneNumber || 'N/A'}</Descriptions.Item>
          <Descriptions.Item label="Country">
            {locations.find(loc => loc.isDefault)?.country || user.location}
          </Descriptions.Item>
          <Descriptions.Item label="Role"><Tag color="gold">{user.userRole}</Tag></Descriptions.Item>
          <Descriptions.Item label="Base Currency">{user.currencyCode || 'Not Set'}</Descriptions.Item>
          <Descriptions.Item label="Assigned Locations">
            {locations.length > 0 ? (
              locations.map(loc => (
                <Tag 
                  key={loc.locationId} 
                  color="cyan" 
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleLocationClick(loc)}
                >
                  {loc.locationName}
                </Tag>
              ))
            ) : (
              <span style={{ color: '#999' }}>No locations assigned</span>
            )}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Modal
        title="Edit Profile Details"
        open={isModalOpen}
        onCancel={() => setIsModalOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setIsModalOpen(false)}>Cancel</Button>,
          <Button key="submit" type="primary" loading={updateLoading} onClick={() => form.submit()}>Save Changes</Button>
        ]}
      >
        <Form form={form} layout="vertical" onFinish={handleUpdateProfile}>
          <Form.Item name="firstName" label="First Name">
            <Input />
          </Form.Item>
          <Form.Item name="lastName" label="Last Name">
            <Input />
          </Form.Item>
          <Form.Item name="emailAddress" label="Email Address" rules={[{ required: true, type: 'email' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="telephoneNumber" label="Contact Number">
            <Input />
          </Form.Item>
          <Form.Item name="roleId" label="Role">
            <Select>
              {roles.map(role => (
                <Select.Option key={role.roleId} value={role.roleId}>{role.roleName}</Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item name="currencyCode" label="Base Currency">
            <Select>
              {currencies.map(curr => (
                <Select.Option key={curr.currencyCode} value={curr.currencyCode}>{curr.currencyName} ({curr.currencyCode})</Select.Option>
              ))}
            </Select>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Add New Location"
        open={isLocationModalOpen}
        onCancel={() => setIsLocationModalOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setIsLocationModalOpen(false)}>Cancel</Button>,
          <Button key="submit" type="primary" loading={locationLoading} onClick={() => locationForm.submit()}>Add Location</Button>
        ]}
      >
        <Form form={locationForm} layout="vertical" onFinish={handleAddLocation}>
          <Form.Item name="locationName" label="Location Name" rules={[{ required: true, message: 'Please enter a location name' }]}>
            <Input placeholder="e.g. Main Gallery" />
          </Form.Item>
          <Form.Item name="addressLine1" label="Address">
            <Input placeholder="Address Line 1" />
          </Form.Item>
          <Form.Item name="city" label="City">
            <Input placeholder="City" />
          </Form.Item>
          <Form.Item name="postcode" label="Postcode">
            <Input placeholder="Postcode" />
          </Form.Item>
          <Form.Item name="country" label="Country">
            <Input placeholder="Country" />
          </Form.Item>
          <Form.Item name="isDefault" valuePropName="checked">
            <Checkbox>Set as Default Location</Checkbox>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Edit Location Details"
        open={isEditLocationModalOpen}
        onCancel={() => setIsEditLocationModalOpen(false)}
        footer={[
          <Button key="delete" type="primary" onClick={handleDeleteLocation} style={{ float: 'left', backgroundColor: '#246A73' }}>Delete</Button>,
          <Button key="cancel" onClick={() => setIsEditLocationModalOpen(false)}>Cancel</Button>,
          <Button key="submit" type="primary" loading={editLocationLoading} onClick={() => editLocationForm.submit()}>Update Location</Button>
        ]}
      >
        <Form form={editLocationForm} layout="vertical" onFinish={handleUpdateLocation}>
          <Form.Item name="locationName" label="Location Name" rules={[{ required: true, message: 'Please enter a location name' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="addressLine1" label="Address">
            <Input />
          </Form.Item>
          <Form.Item name="city" label="City">
            <Input />
          </Form.Item>
          <Form.Item name="postcode" label="Postcode">
            <Input />
          </Form.Item>
          <Form.Item name="country" label="Country">
            <Input />
          </Form.Item>
          <Form.Item name="isDefault" valuePropName="checked">
            <Checkbox>Set as Default Location</Checkbox>
          </Form.Item>
        </Form>
      </Modal>
    </ConfigProvider>
  );
};

export default Profile;
