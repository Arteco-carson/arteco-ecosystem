import React, { useState, useEffect, useContext } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, SafeAreaView, Alert, Modal, FlatList, ActivityIndicator } from 'react-native';
import { ChevronLeft } from 'lucide-react-native';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const CreateDefectReportScreen = ({ navigation }) => {
  const { userToken, logout } = useContext(AuthContext);
  const [reportName, setReportName] = useState('');
  const [selectedCustomer, setSelectedCustomer] = useState(null);
  const [selectedArtwork, setSelectedArtwork] = useState(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectionType, setSelectionType] = useState(null); // 'customer' or 'artwork'
  const [customers, setCustomers] = useState([]);
  const [artworks, setArtworks] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchCustomers();
  }, []);

  const fetchCustomers = async () => {
    try {
      const response = await axios.get(`${BASE_URL}/user/customers`, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      setCustomers(response.data);
    } catch (error) {
      console.error('Error fetching customers:', error);
      if (error.response?.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', 'Failed to load customers.');
      }
    }
  };

  const fetchArtworks = async (customerId) => {
    setLoading(true);
    try {
      const response = await axios.get(`${BASE_URL}/artworks/owner/${customerId}`, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      setArtworks(response.data);
    } catch (error) {
      console.error('Error fetching artworks:', error);
      if (error.response?.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', 'Failed to load artworks for this customer.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleNext = () => {
    if (!selectedCustomer) {
      Alert.alert('Required', 'Please select a customer.');
      return;
    }
    if (!selectedArtwork) {
      Alert.alert('Required', 'Please select an artwork.');
      return;
    }
    if (!reportName.trim()) {
      Alert.alert('Required', 'Please enter a name for the report.');
      return;
    }
    navigation.navigate('CaptureAndAnnotate', { 
      reportName,
      customerId: selectedCustomer.id,
      artworkId: selectedArtwork.id,
      artworkTitle: selectedArtwork.title
    });
  };

  const openSelection = (type) => {
    if (type === 'artwork' && !selectedCustomer) {
      Alert.alert('Select Customer First', 'Please select a customer before choosing an artwork.');
      return;
    }
    setSelectionType(type);
    setModalVisible(true);
  };

  const handleSelect = (item) => {
    if (selectionType === 'customer') {
      setSelectedCustomer(item);
      setSelectedArtwork(null); // Reset artwork when customer changes
      setArtworks([]);
      fetchArtworks(item.id);
    } else {
      setSelectedArtwork(item);
    }
    setModalVisible(false);
  };

  const getListItems = () => {
    if (selectionType === 'customer') return customers;
    if (selectionType === 'artwork') return artworks;
    return [];
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Create New Defect Report</Text>
      </View>
      <View style={styles.content}>
        <Text style={styles.label}>Customer</Text>
        <TouchableOpacity style={styles.selector} onPress={() => openSelection('customer')}>
          <Text style={selectedCustomer ? styles.selectorText : styles.placeholderText}>
            {selectedCustomer ? selectedCustomer.name : 'Select Customer'}
          </Text>
        </TouchableOpacity>

        <Text style={styles.label}>Artwork</Text>
        <TouchableOpacity style={styles.selector} onPress={() => openSelection('artwork')}>
          <Text style={selectedArtwork ? styles.selectorText : styles.placeholderText}>
            {selectedArtwork ? selectedArtwork.title : 'Select Artwork'}
          </Text>
        </TouchableOpacity>

        <Text style={styles.label}>Report Name</Text>
        <TextInput
          style={styles.input}
          placeholder="e.g., 'Damage to Painting XYZ'"
          value={reportName}
          onChangeText={setReportName}
          placeholderTextColor="#94a3b8"
        />
        <TouchableOpacity style={styles.button} onPress={handleNext}>
          <Text style={styles.buttonText}>Next</Text>
        </TouchableOpacity>
      </View>

      <Modal visible={modalVisible} animationType="slide" transparent={true}>
        <View style={styles.modalContainer}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Select {selectionType === 'customer' ? 'Customer' : 'Artwork'}</Text>
            {loading && selectionType === 'artwork' ? (
              <ActivityIndicator size="large" color="#246A73" />
            ) : (
              <FlatList
                data={getListItems()}
                keyExtractor={(item) => item.id.toString()}
                renderItem={({ item }) => (
                  <TouchableOpacity style={styles.modalItem} onPress={() => handleSelect(item)}>
                    <Text style={styles.modalItemText}>{item.name || item.title}</Text>
                  </TouchableOpacity>
                )}
              />
            )}
            <TouchableOpacity style={styles.closeButton} onPress={() => setModalVisible(false)}>
              <Text style={styles.closeButtonText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f0f2f5',
  },
  header: {
    backgroundColor: '#246A73',
    padding: 20,
    alignItems: 'center',
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#fff',
  },
  content: {
    flex: 1,
    padding: 20,
  },
  label: {
    fontSize: 16,
    color: '#1e293b',
    marginBottom: 10,
  },
  input: {
    backgroundColor: 'white',
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 8,
    paddingHorizontal: 15,
    height: 50,
    color: '#1e293b',
    fontSize: 16,
    marginBottom: 20,
  },
  selector: {
    backgroundColor: 'white',
    borderWidth: 1,
    borderColor: '#cbd5e1',
    borderRadius: 8,
    paddingHorizontal: 15,
    height: 50,
    justifyContent: 'center',
    marginBottom: 20,
  },
  selectorText: { color: '#1e293b', fontSize: 16 },
  placeholderText: { color: '#94a3b8', fontSize: 16 },
  button: {
    backgroundColor: '#246A73',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
  },
  buttonText: {
    color: 'white',
    fontWeight: 'bold',
    fontSize: 16,
  },
  modalContainer: { flex: 1, justifyContent: 'flex-end', backgroundColor: 'rgba(0,0,0,0.5)' },
  modalContent: { backgroundColor: 'white', borderTopLeftRadius: 20, borderTopRightRadius: 20, padding: 20, maxHeight: '50%' },
  modalTitle: { fontSize: 20, fontWeight: 'bold', marginBottom: 15, textAlign: 'center', color: '#246A73' },
  modalItem: { paddingVertical: 15, borderBottomWidth: 1, borderBottomColor: '#f0f2f5' },
  modalItemText: { fontSize: 16, color: '#1e293b' },
  closeButton: { marginTop: 20, alignItems: 'center', padding: 10 },
  closeButtonText: { color: '#ef4444', fontSize: 16, fontWeight: 'bold' },
});

export default CreateDefectReportScreen;
