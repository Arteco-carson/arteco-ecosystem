import React, { useState, useEffect, useContext, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ActivityIndicator,
  SafeAreaView,
  KeyboardAvoidingView,
  Platform,
  Modal,
  ScrollView,
  Switch,
  FlatList,
  Image
} from 'react-native';
import axios from 'axios';
import * as ImagePicker from 'expo-image-picker';
import { ChevronLeft, Save, User, MapPin, Layers, Image as ImageIcon, X, Plus, Search, Check, Trash2 } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';
import AddArtistModalScreen from './AddArtistModalScreen';

const AddArtworkModalScreen = ({ visible, onClose, onArtworkCreated }) => {
  const { userToken } = useContext(AuthContext);
  const [loading, setLoading] = useState(false);
  
  // Data Sources
  const [artists, setArtists] = useState([]);
  const [locations, setLocations] = useState([]);
  const [editions, setEditions] = useState([]);

  // Form State
  const [title, setTitle] = useState('');
  const [artistId, setArtistId] = useState(null);
  const [artistName, setArtistName] = useState('');
  const [medium, setMedium] = useState('');
  const [locationId, setLocationId] = useState(null);
  const [locationName, setLocationName] = useState('');
  const [framed, setFramed] = useState(false);
  const [lotNumber, setLotNumber] = useState('');
  const [height, setHeight] = useState('');
  const [width, setWidth] = useState('');
  const [depth, setDepth] = useState('');
  const [weight, setWeight] = useState('');
  const [creationDate, setCreationDate] = useState('');
  const [editionId, setEditionId] = useState(null);
  const [editionName, setEditionName] = useState('');
  const [provenance, setProvenance] = useState('');
  const [cost, setCost] = useState('');
  const [selectedImages, setSelectedImages] = useState([]);

  // Modals State
  const [artistPickerVisible, setArtistPickerVisible] = useState(false);
  const [locationPickerVisible, setLocationPickerVisible] = useState(false);
  const [editionPickerVisible, setEditionPickerVisible] = useState(false);
  const [addArtistModalVisible, setAddArtistModalVisible] = useState(false);
  const [artistSearch, setArtistSearch] = useState('');

  // Fetch Data
  const fetchData = useCallback(async () => {
    if (!visible || !userToken) return;
    try {
      const headers = { Authorization: `Bearer ${userToken}` };
      
      const [artistsRes, locationsRes, editionsRes] = await Promise.all([
        axios.get(`${BASE_URL}/artists`, { headers }),
        axios.get(`${BASE_URL}/locations`, { headers }),
        axios.get(`${BASE_URL}/artworks/editions`, { headers })
      ]);

      setArtists(artistsRes.data);
      setLocations(locationsRes.data);
      setEditions(editionsRes.data);
    } catch (error) {
      console.error('Error fetching form data:', error);
      Alert.alert('Error', 'Failed to load form data.');
    }
  }, [visible, userToken]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Image Picker
  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsMultipleSelection: true,
      quality: 0.8,
    });

    if (!result.canceled) {
      setSelectedImages(prev => [...prev, ...result.assets]);
    }
  };

  const removeImage = (index) => {
    setSelectedImages(prev => prev.filter((_, i) => i !== index));
  };

  // Submit Handler
  const handleCreate = async () => {
    if (!title || !artistId) {
      Alert.alert('Validation', 'Title and Artist are required.');
      return;
    }

    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${userToken}` };
      let imageUrls = [];

      // 1. Upload Images
      if (selectedImages.length > 0) {
        const formData = new FormData();
        selectedImages.forEach((img, index) => {
          formData.append('files', {
            uri: Platform.OS === 'ios' ? img.uri.replace('file://', '') : img.uri,
            type: img.mimeType || 'image/jpeg',
            name: img.fileName || `upload_${index}_${Date.now()}.jpg`,
          });
        });

        const uploadRes = await axios.post(`${BASE_URL}/artworks/upload-images`, formData, {
          headers: { ...headers, 'Content-Type': 'multipart/form-data' },
        });
        imageUrls = uploadRes.data.imageUrls;
      }

      // 2. Create Artwork
      const payload = {
        title,
        artistId,
        medium,
        currentLocationId: locationId,
        frame: framed,
        lotNumber,
        heightCM: height ? parseFloat(height) : null,
        widthCM: width ? parseFloat(width) : null,
        depthCM: depth ? parseFloat(depth) : null,
        weightKG: weight ? parseFloat(weight) : null,
        creationDateDisplay: creationDate,
        editionId,
        provenanceText: provenance,
        acquisitionCost: cost ? parseFloat(cost) : null,
        imageUrls
      };

      const res = await axios.post(`${BASE_URL}/artworks`, payload, { 
        headers: { ...headers, 'Content-Type': 'application/json' } 
      });

      Alert.alert('Success', 'Artwork created successfully.');
      if (onArtworkCreated) onArtworkCreated(res.data);
      resetForm();
      onClose();

    } catch (error) {
      console.error('Create Artwork Error:', error);
      Alert.alert('Error', 'Failed to create artwork.');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setTitle('');
    setArtistId(null);
    setArtistName('');
    setMedium('');
    setLocationId(null);
    setLocationName('');
    setFramed(false);
    setLotNumber('');
    setHeight('');
    setWidth('');
    setDepth('');
    setWeight('');
    setCreationDate('');
    setEditionId(null);
    setEditionName('');
    setProvenance('');
    setCost('');
    setSelectedImages([]);
  };

  const handleArtistCreated = (newArtist) => {
    setArtists(prev => [...prev, newArtist]);
    setArtistId(newArtist.artistId);
    setArtistName(`${newArtist.firstName} ${newArtist.lastName}`);
  };

  // Render Helpers
  const renderSelector = (label, value, placeholder, onPress, icon) => (
    <View style={styles.fieldContainer}>
      <Text style={styles.label}>{label}</Text>
      <TouchableOpacity style={styles.selector} onPress={onPress}>
        <View style={{ flexDirection: 'row', alignItems: 'center' }}>
          {icon}
          <Text style={[styles.selectorText, !value && styles.placeholderText]}>
            {value || placeholder}
          </Text>
        </View>
      </TouchableOpacity>
    </View>
  );

  const filteredArtists = artists.filter(a => 
    `${a.firstName} ${a.lastName}`.toLowerCase().includes(artistSearch.toLowerCase())
  );

  return (
    <Modal visible={visible} animationType="slide" presentationStyle="pageSheet">
      <SafeAreaView style={styles.container}>
        <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={{ flex: 1 }}>
          
          {/* Header */}
          <View style={styles.header}>
            <TouchableOpacity onPress={onClose} style={styles.backButton}>
              <Text style={styles.backButtonText}>Cancel</Text>
            </TouchableOpacity>
            <Text style={styles.headerTitle}>New Artwork</Text>
            <TouchableOpacity onPress={handleCreate} disabled={loading}>
              {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveButtonText}>Save</Text>}
            </TouchableOpacity>
          </View>

          <ScrollView contentContainerStyle={styles.formContainer}>
            
            {/* Title */}
            <Text style={styles.label}>Title *</Text>
            <TextInput style={styles.input} value={title} onChangeText={setTitle} placeholder="Artwork Title" />

            {/* Artist Selector */}
            {renderSelector("Artist *", artistName, "Select Artist", () => setArtistPickerVisible(true), <User size={18} color="#64748b" style={{ marginRight: 8 }} />)}

            {/* Medium */}
            <Text style={styles.label}>Medium</Text>
            <TextInput style={styles.input} value={medium} onChangeText={setMedium} placeholder="Oil on Canvas, etc." />

            {/* Location Selector */}
            {renderSelector("Location", locationName, "Select Location", () => setLocationPickerVisible(true), <MapPin size={18} color="#64748b" style={{ marginRight: 8 }} />)}

            {/* Framed Switch */}
            <View style={styles.switchRow}>
              <Text style={styles.label}>Framed</Text>
              <Switch value={framed} onValueChange={setFramed} trackColor={{ false: "#cbd5e1", true: "#246A73" }} />
            </View>

            {/* Lot Number */}
            <Text style={styles.label}>Lot Number</Text>
            <TextInput style={styles.input} value={lotNumber} onChangeText={setLotNumber} placeholder="e.g. Lot 452" />

            {/* Dimensions */}
            <Text style={styles.label}>Dimensions (cm)</Text>
            <View style={styles.row}>
              <TextInput style={[styles.input, styles.flexInput]} value={height} onChangeText={setHeight} placeholder="Height" keyboardType="numeric" />
              <View style={{ width: 10 }} />
              <TextInput style={[styles.input, styles.flexInput]} value={width} onChangeText={setWidth} placeholder="Width" keyboardType="numeric" />
              <View style={{ width: 10 }} />
              <TextInput style={[styles.input, styles.flexInput]} value={depth} onChangeText={setDepth} placeholder="Depth" keyboardType="numeric" />
            </View>

            {/* Weight */}
            <Text style={styles.label}>Weight (kg)</Text>
            <TextInput style={styles.input} value={weight} onChangeText={setWeight} placeholder="0.0" keyboardType="numeric" />

            {/* Creation Date */}
            <Text style={styles.label}>Creation Date</Text>
            <TextInput style={styles.input} value={creationDate} onChangeText={setCreationDate} placeholder="e.g. 2023" />

            {/* Edition Selector */}
            {renderSelector("Edition Type", editionName, "Select Edition", () => setEditionPickerVisible(true), <Layers size={18} color="#64748b" style={{ marginRight: 8 }} />)}

            {/* Provenance */}
            <Text style={styles.label}>Provenance</Text>
            <TextInput style={[styles.input, styles.textArea]} value={provenance} onChangeText={setProvenance} multiline numberOfLines={3} textAlignVertical="top" />

            {/* Cost */}
            <Text style={styles.label}>Acquisition Cost (£)</Text>
            <TextInput style={styles.input} value={cost} onChangeText={setCost} placeholder="0.00" keyboardType="numeric" />

            {/* Images */}
            <Text style={styles.label}>Artwork Images</Text>
            <View style={styles.imageSection}>
              <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                <TouchableOpacity style={styles.addImageButton} onPress={pickImage}>
                  <Plus size={24} color="#64748b" />
                  <Text style={styles.addImageText}>Add</Text>
                </TouchableOpacity>
                {selectedImages.map((img, index) => (
                  <View key={index} style={styles.imagePreview}>
                    <Image source={{ uri: img.uri }} style={styles.thumb} />
                    <TouchableOpacity style={styles.removeImage} onPress={() => removeImage(index)}>
                      <X size={12} color="#fff" />
                    </TouchableOpacity>
                  </View>
                ))}
              </ScrollView>
            </View>

            <View style={{ height: 40 }} />
          </ScrollView>

          {/* --- ARTIST PICKER MODAL --- */}
          <Modal visible={artistPickerVisible} animationType="slide" presentationStyle="pageSheet">
            <SafeAreaView style={styles.modalContainer}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Select Artist</Text>
                <TouchableOpacity onPress={() => setArtistPickerVisible(false)}>
                  <Text style={styles.closeText}>Close</Text>
                </TouchableOpacity>
              </View>
              <View style={styles.searchContainer}>
                <Search size={20} color="#94a3b8" />
                <TextInput 
                  style={styles.searchInput} 
                  placeholder="Search artists..." 
                  value={artistSearch}
                  onChangeText={setArtistSearch}
                />
              </View>
              <TouchableOpacity style={styles.addNewItemButton} onPress={() => setAddArtistModalVisible(true)}>
                <Plus size={20} color="#246A73" />
                <Text style={styles.addNewItemText}>Add New Artist</Text>
              </TouchableOpacity>
              <FlatList
                data={filteredArtists}
                keyExtractor={item => item.artistId.toString()}
                renderItem={({ item }) => (
                  <TouchableOpacity style={styles.pickerItem} onPress={() => {
                    setArtistId(item.artistId);
                    setArtistName(`${item.firstName} ${item.lastName}`);
                    setArtistPickerVisible(false);
                  }}>
                    <Text style={styles.pickerItemText}>{item.firstName} {item.lastName}</Text>
                    {artistId === item.artistId && <Check size={20} color="#246A73" />}
                  </TouchableOpacity>
                )}
              />
            </SafeAreaView>
          </Modal>

          {/* --- LOCATION PICKER MODAL --- */}
          <Modal visible={locationPickerVisible} animationType="slide" presentationStyle="pageSheet">
            <SafeAreaView style={styles.modalContainer}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Select Location</Text>
                <TouchableOpacity onPress={() => setLocationPickerVisible(false)}>
                  <Text style={styles.closeText}>Close</Text>
                </TouchableOpacity>
              </View>
              <FlatList
                data={locations}
                keyExtractor={item => item.locationId.toString()}
                renderItem={({ item }) => (
                  <TouchableOpacity style={styles.pickerItem} onPress={() => {
                    setLocationId(item.locationId);
                    setLocationName(item.locationName);
                    setLocationPickerVisible(false);
                  }}>
                    <Text style={styles.pickerItemText}>{item.locationName}</Text>
                    {locationId === item.locationId && <Check size={20} color="#246A73" />}
                  </TouchableOpacity>
                )}
              />
            </SafeAreaView>
          </Modal>

          {/* --- EDITION PICKER MODAL --- */}
          <Modal visible={editionPickerVisible} animationType="slide" presentationStyle="pageSheet">
            <SafeAreaView style={styles.modalContainer}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Select Edition</Text>
                <TouchableOpacity onPress={() => setEditionPickerVisible(false)}>
                  <Text style={styles.closeText}>Close</Text>
                </TouchableOpacity>
              </View>
              <FlatList
                data={editions}
                keyExtractor={item => (item.editionId || item.EditionId).toString()}
                renderItem={({ item }) => {
                  const id = item.editionId || item.EditionId;
                  const type = item.editionType || item.EditionType;
                  const marking = item.marking || item.Marking;
                  return (
                    <TouchableOpacity style={styles.pickerItem} onPress={() => {
                      setEditionId(id);
                      setEditionName(`${type} - ${marking}`);
                      setEditionPickerVisible(false);
                    }}>
                      <Text style={styles.pickerItemText}>{type} - {marking}</Text>
                      {editionId === id && <Check size={20} color="#246A73" />}
                    </TouchableOpacity>
                  );
                }}
              />
            </SafeAreaView>
          </Modal>

          {/* --- ADD ARTIST MODAL (Nested) --- */}
          <AddArtistModalScreen 
            visible={addArtistModalVisible}
            onClose={() => setAddArtistModalVisible(false)}
            onArtistCreated={handleArtistCreated}
          />

        </KeyboardAvoidingView>
      </SafeAreaView>
    </Modal>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
  backButton: { padding: 5 },
  backButtonText: { color: '#fff', fontSize: 16 },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
  saveButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
  formContainer: { padding: 20 },
  fieldContainer: { marginBottom: 12 },
  label: { fontSize: 14, fontWeight: '600', color: '#475569', marginBottom: 6, marginTop: 6 },
  input: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12, fontSize: 16, color: '#1e293b' },
  selector: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12 },
  selectorText: { fontSize: 16, color: '#1e293b' },
  placeholderText: { color: '#94a3b8' },
  switchRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginVertical: 10, backgroundColor: '#fff', padding: 12, borderRadius: 8, borderWidth: 1, borderColor: '#cbd5e1' },
  row: { flexDirection: 'row' },
  flexInput: { flex: 1 },
  textArea: { height: 80 },
  imageSection: { flexDirection: 'row', marginTop: 8 },
  addImageButton: { width: 80, height: 80, backgroundColor: '#e2e8f0', borderRadius: 8, justifyContent: 'center', alignItems: 'center', marginRight: 10, borderStyle: 'dashed', borderWidth: 1, borderColor: '#94a3b8' },
  addImageText: { fontSize: 12, color: '#64748b', marginTop: 4 },
  imagePreview: { width: 80, height: 80, marginRight: 10, borderRadius: 8, overflow: 'hidden' },
  thumb: { width: '100%', height: '100%' },
  removeImage: { position: 'absolute', top: 4, right: 4, backgroundColor: 'rgba(0,0,0,0.6)', borderRadius: 10, padding: 4 },
  
  // Modal Styles
  modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
  modalHeader: { padding: 16, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
  modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
  closeText: { color: '#246A73', fontSize: 16, fontWeight: '600' },
  pickerItem: { padding: 16, backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#f1f5f9', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  pickerItemText: { fontSize: 16, color: '#334155' },
  searchContainer: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', padding: 10, borderBottomWidth: 1, borderColor: '#e2e8f0' },
  searchInput: { flex: 1, marginLeft: 10, fontSize: 16, color: '#1e293b' },
  addNewItemButton: { flexDirection: 'row', alignItems: 'center', padding: 16, backgroundColor: '#f0fdfa', borderBottomWidth: 1, borderColor: '#ccfbf1' },
  addNewItemText: { marginLeft: 10, color: '#246A73', fontWeight: 'bold', fontSize: 16 }
});

export default AddArtworkModalScreen;