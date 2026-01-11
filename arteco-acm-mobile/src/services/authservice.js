import api from './api';

export const login = async (username, password) => {
  const response = await api.post('/auth/login', { username, password });
  return response.data; // Returns { Token, Username, Role }
};

export const register = async (userData) => {
  // userData matches RegistrationRequest.cs (FirstName, LastName, ExternalUserId, etc.)
  const response = await api.post('/auth/register', userData);
  return response.data;
};