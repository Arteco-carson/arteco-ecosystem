import React, { useEffect, useState, useContext } from 'react';
import {
  View,
  Text,
  ScrollView,
  Image,
  StyleSheet,
  ActivityIndicator,
  TouchableOpacity,
  Alert,
  Dimensions,
  FlatList,
  SafeAreaView,
  Modal,
  Platform
} from 'react-native';
import axios from 'axios';
import * as ImagePicker from 'expo-image-picker';
import { useNavigation, useRoute } from '@react-navigation/native';
import { Upload, X, Image as ImageIcon } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const { width } = Dimensions.get('window');

const ArtworkDetailsScreen = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const { id } = route.params; // Expecting { id: 123 } passed via navigation
  const { userToken, logout } = useContext(AuthContext);

  const [artwork, setArtwork] = useState(null);
  const [loading, setLoading] = useState(true);
  const [defectReports, setDefectReports] = useState([]);
  
  // Image Upload State
  const [uploadModalVisible, setUploadModalVisible] = useState(false);
  const [selectedImage, setSelectedImage] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  // Fetch Data
  useEffect(() => {
    const fetchData = async () => {
      if (!userToken) return;
      
      setLoading(true);
      try {
        const headers = { Authorization: `Bearer ${userToken}` };
        
        // Fetch Artwork Details
        const artRes = await axios.get(`${BASE_URL}/artworks/${id}`, { headers });
        setArtwork(artRes.data);

        // Fetch Defect Reports
        try {
            const defectRes = await axios.get(`${BASE_URL}/DefectReports/artwork/${id}`, { headers });
            setDefectReports(defectRes.data);
        } catch (e) {
            // Ignore 404 or empty responses for defects
            setDefectReports([]);
        }

      } catch (error) {
        console.error('Error fetching details:', error);
        if (error.response?.status === 401) {
            Alert.alert('Session Expired', 'Please log in again.');
            logout();
        } else {
            Alert.alert('Error', 'Failed to load artwork details.');
            navigation.goBack();
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id, userToken, logout, navigation, refreshKey]);

  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true,
      aspect: [4, 3],
      quality: 0.8,
    });

    if (!result.canceled) {
      setSelectedImage(result.assets[0]);
    }
  };

  const handleUploadImage = async () => {
    if (!selectedImage) return;
    setUploading(true);

    try {
      const formData = new FormData();
      formData.append('files', {
        uri: Platform.OS === 'ios' ? selectedImage.uri.replace('file://', '') : selectedImage.uri,
        type: selectedImage.mimeType || 'image/jpeg',
        name: selectedImage.fileName || `upload_${Date.now()}.jpg`,
      });

      const headers = { 
        'Authorization': `Bearer ${userToken}`,
        'Content-Type': 'multipart/form-data',
      };

      const uploadRes = await axios.post(`${BASE_URL}/artworks/upload-images`, formData, { headers });
      
      const linkPayload = uploadRes.data.imageUrls;
      await axios.post(`${BASE_URL}/artworks/${id}/images`, linkPayload, { 
        headers: { 'Authorization': `Bearer ${userToken}` } 
      });

      Alert.alert('Success', 'Image uploaded successfully');
      setUploadModalVisible(false);
      setSelectedImage(null);
      setRefreshKey(prev => prev + 1);
    } catch (error) {
      console.error('Upload failed', error);
      Alert.alert('Error', 'Failed to upload image');
    } finally {
      setUploading(false);
    }
  };

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#246A73" />
      </View>
    );
  }

  if (!artwork) {
    return (
      <View style={styles.center}>
        <Text>Artwork not found.</Text>
      </View>
    );
  }

  const renderImageItem = ({ item }) => (
    <View style={styles.imageContainer}>
      <Image 
        source={{ uri: item.blobUrl }} 
        style={styles.image} 
        resizeMode="contain" 
      />
    </View>
  );

  const edition = artwork.edition || artwork.Edition;

  return (
    <SafeAreaView style={styles.container}>
        {/* Header */}
        <View style={styles.header}>
            <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
                <Text style={styles.backButtonText}>← Back</Text>
            </TouchableOpacity>
            <Text style={styles.headerTitle} numberOfLines={1}>Artwork Details</Text>
            <View style={{width: 50}} /> 
        </View>

        <ScrollView contentContainerStyle={styles.scrollContent}>
            {/* Image Carousel */}
            <View style={styles.carouselContainer}>
                {artwork.artworkImages && artwork.artworkImages.length > 0 ? (
                    <FlatList
                        data={artwork.artworkImages}
                        renderItem={renderImageItem}
                        keyExtractor={(item, index) => index.toString()}
                        horizontal
                        pagingEnabled
                        showsHorizontalScrollIndicator={false}
                    />
                ) : (
                    <View style={[styles.imageContainer, { backgroundColor: '#f1f5f9' }]}>
                        <Text style={{ color: '#94a3b8' }}>No Image Available</Text>
                    </View>
                )}
            </View>

            <TouchableOpacity 
                style={styles.uploadImageButton} 
                onPress={() => setUploadModalVisible(true)}
            >
                <Upload size={16} color="#fff" />
                <Text style={styles.uploadImageButtonText}>Update Artwork Images</Text>
            </TouchableOpacity>

            {/* Main Details */}
            <View style={styles.section}>
                <Text style={styles.idText}>Artwork Record #{artwork.artworkId}</Text>
                <Text style={styles.title}>{artwork.title}</Text>
                
                <View style={styles.row}>
                    <Text style={styles.label}>Artist:</Text>
                    <Text style={[styles.value, { color: '#246A73', fontWeight: 'bold' }]}>{artwork.artistName || 'Unknown'}</Text>
                </View>

                {artwork.collections && artwork.collections.length > 0 && (
                    <View style={styles.row}>
                        <Text style={styles.label}>Collection:</Text>
                        <Text style={styles.value}>{artwork.collections.join(', ')}</Text>
                    </View>
                )}

                <View style={styles.row}>
                    <Text style={styles.label}>Location:</Text>
                    <Text style={styles.value}>{artwork.locationName || 'Not Assigned'}</Text>
                </View>

                <View style={styles.row}>
                    <Text style={styles.label}>Medium:</Text>
                    <Text style={styles.value}>{artwork.medium || 'N/A'}</Text>
                </View>

                <View style={styles.row}>
                    <Text style={styles.label}>Dimensions:</Text>
                    <Text style={styles.value}>{artwork.heightCM} x {artwork.widthCM} cm</Text>
                </View>
            </View>

            {/* Edition Details */}
            {edition && (
                <View style={styles.section}>
                    <Text style={styles.sectionHeader}>Edition Details</Text>
                    <View style={styles.grid}>
                        <View style={styles.gridItem}>
                            <Text style={styles.gridLabel}>Type</Text>
                            <Text style={styles.gridValue}>{edition.editionType || 'N/A'}</Text>
                        </View>
                        <View style={styles.gridItem}>
                            <Text style={styles.gridLabel}>Marking</Text>
                            <Text style={styles.gridValue}>{edition.marking || 'N/A'}</Text>
                        </View>
                    </View>
                </View>
            )}

            {/* Valuation */}
            <View style={styles.section}>
                <View style={styles.valuationHeader}>
                    <Text style={[styles.sectionHeader, { marginBottom: 0 }]}>Current Valuation</Text>
                    <TouchableOpacity 
                        style={styles.updateButton}
                        onPress={() => navigation.navigate('AddAppraisal', { artworkId: artwork.artworkId })}
                    >
                        <Text style={styles.updateButtonText}>Update Valuation</Text>
                    </TouchableOpacity>
                </View>
                <Text style={styles.valuation}>£{artwork.acquisitionCost?.toLocaleString('en-GB')}</Text>
            </View>

            {/* Provenance */}
            <View style={styles.section}>
                <Text style={styles.sectionHeader}>Provenance History</Text>
                <Text style={styles.bodyText}>
                    {artwork.provenanceText || 'No provenance history recorded.'}
                </Text>
                <View style={styles.statusBadge}>
                    <Text style={styles.statusText}>Status: {artwork.status || 'Managed Asset'}</Text>
                </View>
            </View>

            {/* Defect Reports */}
            {defectReports.length > 0 && (
                <View style={styles.section}>
                    <Text style={styles.sectionHeader}>Defect Reports</Text>
                    {defectReports.map((report) => (
                        <View key={report.defectReportId} style={styles.reportItem}>
                            <Text style={styles.reportDate}>{new Date(report.createdDate).toLocaleDateString()}</Text>
                            <Text style={styles.reportBy}>By: {report.createdBy}</Text>
                        </View>
                    ))}
                </View>
            )}

        </ScrollView>

        {/* Upload Modal */}
        <Modal
            visible={uploadModalVisible}
            animationType="slide"
            presentationStyle="pageSheet"
        >
            <View style={styles.modalContainer}>
                <View style={styles.modalHeader}>
                    <Text style={styles.modalTitle}>Upload Image</Text>
                    <TouchableOpacity onPress={() => setUploadModalVisible(false)}>
                        <X size={24} color="#1e293b" />
                    </TouchableOpacity>
                </View>
                
                <View style={styles.modalContent}>
                    <TouchableOpacity style={styles.imagePickerPlaceholder} onPress={pickImage}>
                        {selectedImage ? (
                            <Image source={{ uri: selectedImage.uri }} style={styles.previewImage} resizeMode="contain" />
                        ) : (
                            <View style={styles.placeholderContent}>
                                <ImageIcon size={48} color="#94a3b8" />
                                <Text style={styles.placeholderText}>Tap to select an image</Text>
                            </View>
                        )}
                    </TouchableOpacity>

                    <TouchableOpacity 
                        style={[styles.modalButton, (!selectedImage || uploading) && styles.disabledButton]}
                        onPress={handleUploadImage}
                        disabled={!selectedImage || uploading}
                    >
                        {uploading ? <ActivityIndicator color="#fff" /> : <Text style={styles.modalButtonText}>Upload Image</Text>}
                    </TouchableOpacity>
                </View>
            </View>
        </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
    container: { flex: 1, backgroundColor: '#f8fafc' },
    center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
    header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
    backButton: { padding: 5 },
    backButtonText: { color: '#fff', fontSize: 16 },
    headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
    scrollContent: { paddingBottom: 80 },
    carouselContainer: { height: 300, backgroundColor: '#e2e8f0' },
    imageContainer: { width: width, height: 300, justifyContent: 'center', alignItems: 'center' },
    image: { width: '100%', height: '100%' },
    section: { backgroundColor: '#fff', padding: 20, marginTop: 10, borderTopWidth: 1, borderBottomWidth: 1, borderColor: '#e2e8f0' },
    idText: { color: '#3b82f6', fontWeight: 'bold', fontSize: 12, textTransform: 'uppercase', marginBottom: 5 },
    title: { fontSize: 24, fontWeight: 'bold', color: '#1e293b', marginBottom: 15 },
    row: { flexDirection: 'row', marginBottom: 8 },
    label: { fontWeight: '600', color: '#475569', width: 100 },
    value: { color: '#334155', flex: 1 },
    sectionHeader: { fontSize: 18, fontWeight: '600', color: '#475569', marginBottom: 10 },
    grid: { flexDirection: 'row', flexWrap: 'wrap' },
    gridItem: { width: '50%', marginBottom: 10 },
    gridLabel: { fontSize: 12, color: '#64748b' },
    gridValue: { fontSize: 14, color: '#334155', fontWeight: '500' },
    valuation: { fontSize: 28, fontWeight: 'bold', color: '#059669' },
    valuationHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 },
    updateButton: { backgroundColor: '#246A73', paddingHorizontal: 12, paddingVertical: 6, borderRadius: 6 },
    updateButtonText: { color: '#fff', fontSize: 12, fontWeight: 'bold' },
    bodyText: { fontSize: 14, color: '#64748b', lineHeight: 20 },
    statusBadge: { marginTop: 15, backgroundColor: '#f0fdf4', padding: 8, borderRadius: 4, alignSelf: 'flex-start' },
    statusText: { color: '#166534', fontWeight: '600' },
    reportItem: { padding: 10, backgroundColor: '#f1f5f9', borderRadius: 6, marginBottom: 8 },
    reportDate: { fontWeight: 'bold', color: '#334155' },
    reportBy: { fontSize: 12, color: '#64748b' },
    uploadImageButton: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', backgroundColor: '#246A73', padding: 12, margin: 16, borderRadius: 8, gap: 8 },
    uploadImageButtonText: { color: '#fff', fontWeight: 'bold', fontSize: 16 },
    modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
    modalHeader: { padding: 16, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
    modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
    modalContent: { padding: 20, flex: 1 },
    imagePickerPlaceholder: { height: 300, backgroundColor: '#e2e8f0', borderRadius: 12, justifyContent: 'center', alignItems: 'center', marginBottom: 20, overflow: 'hidden', borderStyle: 'dashed', borderWidth: 2, borderColor: '#cbd5e1' },
    previewImage: { width: '100%', height: '100%' },
    placeholderContent: { alignItems: 'center', gap: 10 },
    placeholderText: { color: '#64748b', fontSize: 16 },
    modalButton: { backgroundColor: '#246A73', padding: 16, borderRadius: 8, alignItems: 'center' },
    disabledButton: { backgroundColor: '#94a3b8' },
    modalButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' }
});

export default ArtworkDetailsScreen;