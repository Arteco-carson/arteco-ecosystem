import { Platform } from 'react-native';
import { API_URL } from '@env';

// For local development, you might want to use different URLs for Android and iOS.
// However, for production, it will be a single URL.
const androidDevelopmentUrl = 'http://10.0.2.2:5240/api';
const iosDevelopmentUrl = 'http://localhost:5240/api';

const developmentUrl = Platform.OS === 'android' ? androidDevelopmentUrl : iosDevelopmentUrl;

export const BASE_URL = API_URL || developmentUrl;