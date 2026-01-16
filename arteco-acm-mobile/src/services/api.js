// src/services/api.js
import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

import { BASE_URL } from '../config/env';

const API_BASE_URL = BASE_URL; 

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000, // 10 second timeout is standard for UK management apps
  headers: {
    'Content-Type': 'application/json',
  },
});

// Senior Management Tip: Log the exact error to the console to see if it's a 404, 500, or Timeout
api.interceptors.response.use(
  response => response,
  error => {
    console.error("[Network Debug]:", error.message);
    if (error.code === 'ECONNABORTED') {
      console.error("The request timed out. Check your Firewall/Network.");
    }
    return Promise.reject(error);
  }
);

api.interceptors.request.use(async (config) => {
  const token = await AsyncStorage.getItem('userToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;