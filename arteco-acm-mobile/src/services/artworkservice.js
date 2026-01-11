import api from './api';

/**
 * Utility to format numbers as GBP for the UI.
 * As a senior manager, standardising this at the service level 
 * ensures consistent financial reporting across the app.
 */
export const formatToGBP = (amount) => {
  return new Intl.NumberFormat('en-GB', {
    style: 'currency',
    currency: 'GBP',
  }).format(amount);
};

export const getArtworks = async () => {
  try {
    const response = await api.get('/artworks');
    return response.data;
  } catch (error) {
    console.error("Failed to fetch artworks:", error);
    throw error;
  }
};

export const updateValuation = async (id, newValuation) => {
  // Ensure the valuation is a valid number before sending to the C# backend
  const numericValuation = parseFloat(newValuation);
  
  if (isNaN(numericValuation)) {
    throw new Error("Invalid valuation amount provided.");
  }

  try {
    const response = await api.post(`/artworks/update-valuation/${id}`, {
      newValuation: numericValuation,
      effectiveDate: new Date().toISOString() // ISO format for .NET DateTime compatibility
    });
    return response.data;
  } catch (error) {
    console.error(`Failed to update valuation for artwork ${id}:`, error);
    throw error;
  }
};