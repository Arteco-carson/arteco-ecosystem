import React, { useState } from 'react';
import { Modal, Form, Input, Button, InputNumber, Space, message } from 'antd';
import axios from 'axios';
import API_URL from './api';

const { TextArea } = Input;

const AddArtistModal = ({ visible, onClose, onArtistCreated }) => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);

    const handleCreateArtist = async (values) => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                message.error('Authentication token not found.');
                return;
            }
            const headers = { Authorization: `Bearer ${token.trim()}` };
            const res = await axios.post(`${API_URL}/api/artists`, values, { headers });
            const newArtist = res.data;
            
            message.success(`Artist "${newArtist.firstName} ${newArtist.lastName}" created.`);
            form.resetFields();
            if (onArtistCreated) {
                onArtistCreated(newArtist);
            }
            onClose();
        } catch (error) {
            console.error('Failed to create artist:', error);
            message.error('Failed to create new artist.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Modal
            title="Create New Artist"
            open={visible}
            onCancel={onClose}
            footer={[
                <Button key="back" onClick={onClose}>
                    Cancel
                </Button>,
                <Button key="submit" type="primary" loading={loading} onClick={() => form.submit()}>
                    Create Artist
                </Button>,
            ]}
        >
            <Form form={form} layout="vertical" onFinish={handleCreateArtist}>
                <Form.Item name="firstName" label="First Name">
                    <Input />
                </Form.Item>
                <Form.Item name="lastName" label="Last Name" rules={[{ required: true, message: "Last name is required."}]}>
                    <Input />
                </Form.Item>
                <Form.Item name="pseudonym" label="Pseudonym">
                    <Input />
                </Form.Item>
                <Form.Item name="nationality" label="Nationality">
                    <Input />
                </Form.Item>
                <Space>
                    <Form.Item name="birthYear" label="Birth Year">
                        <InputNumber />
                    </Form.Item>
                    <Form.Item name="deathYear" label="Death Year">
                        <InputNumber />
                    </Form.Item>
                </Space>
                <Form.Item name="biography" label="Biography">
                    <TextArea rows={4} />
                </Form.Item>
            </Form>
        </Modal>
    );
};

export default AddArtistModal;
