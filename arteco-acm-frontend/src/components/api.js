let apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:5240';

// Remove any trailing slash to prevent double slashes in requests
if (apiUrl.endsWith('/')) {
  apiUrl = apiUrl.slice(0, -1);
}
const API_URL = apiUrl;

export default API_URL;
