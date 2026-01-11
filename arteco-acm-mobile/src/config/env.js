import { IS_PRODUCTION, API_URL } from '@env';

export const BASE_URL = API_URL || 'http://localhost:5240/api';
export { IS_PRODUCTION };