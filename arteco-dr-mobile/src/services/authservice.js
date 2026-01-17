import api from './api';

export const login = async (username, password) => {
  const response = await api.post('/auth/login-dr', { username, password }, {
    headers: {
      'Content-Type': 'application/json'
    }
  });
  return response.data; // Returns { Token, Username, Role }
};

export const register = async (userData) => {
  // userData for register-dr just needs { username, password, email, firstName, lastName }
  const response = await api.post('/auth/register-dr', userData);
  return response.data;
};

export const resetPassword = async (passwordData) => {
  const response = await api.post('/auth/reset-password', passwordData);
  return response.data;
};
