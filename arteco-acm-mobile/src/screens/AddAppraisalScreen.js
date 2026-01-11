import React, { useState, useEffect, useContext } from 'react';
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
  FlatList,
  ScrollView
} from 'react-native';
import { useNavigation, useRoute } from '@react-navigation/native';
import { ChevronLeft, Save, User, BadgePoundSterling, Palette, X, Check } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const AddAppraisalScreen = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const { userToken, logout } = useContext(AuthContext);
  
  // Pre-select artwork if passed via navigation parameters
  const initialArtworkId = route.params?.artworkId;

  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  
  // Data
  const [artworks, setArtworks] = useState([]);
  
  // Form State
  const [selectedArtworkId, setSelectedArtworkId] = useState(initialArtworkId || null);
  const [selectedArtworkTitle, setSelectedArtworkTitle] = useState('');
  const [valuationAmount, setValuationAmount] = useState('');
  const [appraiserName, setAppraiserName] = useState('');
  const [notes, setNotes] = useState('');
  
  // Modal State
  const [modalVisible, setModalVisible] = useState(false);

  useEffect(() => {
    fetchArtworks();
  }, []);

  // When artworks load, if we have an initial ID, set the title automatically
  useEffect(() => {
    if (initialArtworkId && artworks.length > 0) {
      const art = artworks.find(a => a.artworkId == initialArtworkId);
      if (art) {
        setSelectedArtworkTitle(art.title);
        setSelectedArtworkId(art.artworkId);
      }
    }
  }, [artworks, initialArtworkId]);

  const fetchArtworks = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${BASE_URL}/artworks`, {
        headers: { 
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setArtworks(data);
        
        // If manually selecting from list later, we need the title
        if (selectedArtworkId) {
             const art = data.find(a => a.artworkId == selectedArtworkId);
             if (art) setSelectedArtworkTitle(art.title);
        }
      } else if (response.status === 401) {
        logout();
      } else {
        Alert.alert('Error', 'Failed to load artworks.');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Network error loading artworks.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectArtwork = (item) => {
    setSelectedArtworkId(item.artworkId);
    setSelectedArtworkTitle(item.title);
    setModalVisible(false);
  };

  const handleSubmit = async () => {
    if (!selectedArtworkId || !valuationAmount || !appraiserName) {
      Alert.alert('Validation', 'Please fill in all required fields.');
      return;
    }

    setSubmitting(true);
    
    const numericValuation = parseFloat(valuationAmount);

    const payload = {
      artworkId: parseInt(selectedArtworkId),
      valuationAmount: numericValuation,
      insuranceValue: numericValuation, // Defaulting to valuation as per web logic
      valuationDate: new Date().toISOString().split('T')[0],
      appraiserName: appraiserName,
      notes: notes
    };

    try {
      const response = await fetch(`${BASE_URL}/appraisals`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        Alert.alert('Success', 'Appraisal recorded successfully.', [
          { text: 'OK', onPress: () => navigation.goBack() }
        ]);
      } else {
        Alert.alert('Error', 'Failed to save appraisal.');
      }
    } catch (error) {
      Alert.alert('Error', 'Network error saving appraisal.');
    } finally {
      setSubmitting(false);
    }
  };

  const renderArtworkModalItem = ({ item }) => (
    <TouchableOpacity 
        style={styles.modalItem} 
        onPress={() => handleSelectArtwork(item)}
    >
        <Text style={styles.modalItemText}>{item.title}</Text>
        {item.artworkId === selectedArtworkId ? <Check size={20} color="#246A73" /> : null}
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView 
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        style={{ flex: 1 }}
      >
        <View style={styles.header}>
            <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
                <ChevronLeft size={24} color="#fff" />
                <Text style={styles.backButtonText}>Back</Text>
            </TouchableOpacity>
            <Text style={styles.headerTitle}>Add Appraisal</Text>
            <View style={{ width: 60 }} />
        </View>

        <ScrollView contentContainerStyle={styles.formContainer}>
            
            {/* Artwork Selector */}
            <Text style={styles.label}>Select Artwork</Text>
            <TouchableOpacity 
                style={styles.selector} 
                onPress={() => setModalVisible(true)}
            >
                <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                    <Palette size={20} color="#94a3b8" style={{ marginRight: 10 }} />
                    <Text style={selectedArtworkTitle ? styles.selectorText : styles.placeholderText}>
                        {selectedArtworkTitle || "Select an artwork..."}
                    </Text>
                </View>
            </TouchableOpacity>

            {/* Valuation Amount */}
            <Text style={styles.label}>New Acquisition Cost (£)</Text>
            <View style={styles.inputContainer}>
                <BadgePoundSterling size={20} color="#94a3b8" style={styles.inputIcon} />
                <TextInput
                    style={styles.input}
                    value={valuationAmount}
                    onChangeText={setValuationAmount}
                    placeholder="0.00"
                    keyboardType="numeric"
                    placeholderTextColor="#cbd5e1"
                />
            </View>

            {/* Appraiser Name */}
            <Text style={styles.label}>Appraiser Name</Text>
            <View style={styles.inputContainer}>
                <User size={20} color="#94a3b8" style={styles.inputIcon} />
                <TextInput
                    style={styles.input}
                    value={appraiserName}
                    onChangeText={setAppraiserName}
                    placeholder="Enter appraiser name"
                    placeholderTextColor="#cbd5e1"
                />
            </View>

            {/* Notes */}
            <Text style={styles.label}>Compliance Notes</Text>
            <TextInput
                style={[styles.input, styles.textArea]}
                value={notes}
                onChangeText={setNotes}
                placeholder="Enter notes..."
                multiline
                numberOfLines={4}
                textAlignVertical="top"
                placeholderTextColor="#cbd5e1"
            />

            <TouchableOpacity 
                style={[styles.submitButton, submitting && styles.disabledButton]}
                onPress={handleSubmit}
                disabled={submitting}
            >
                {submitting ? (
                    <ActivityIndicator color="#fff" />
                ) : (
                    <>
                        <Save size={20} color="#fff" style={{ marginRight: 8 }} />
                        <Text style={styles.submitButtonText}>Update Appraisal</Text>
                    </>
                )}
            </TouchableOpacity>

        </ScrollView>

        {/* Artwork Selection Modal */}
        <Modal
            visible={modalVisible}
            animationType="slide"
            presentationStyle="pageSheet"
        >
            <View style={styles.modalContainer}>
                <View style={styles.modalHeader}>
                    <Text style={styles.modalTitle}>Select Artwork</Text>
                    <TouchableOpacity onPress={() => setModalVisible(false)}>
                        <X size={24} color="#1e293b" />
                    </TouchableOpacity>
                </View>
                {loading ? (
                    <ActivityIndicator size="large" color="#246A73" style={{ marginTop: 20 }} />
                ) : (
                    <FlatList
                        data={artworks}
                        keyExtractor={item => item.artworkId.toString()}
                        renderItem={renderArtworkModalItem}
                        contentContainerStyle={{ padding: 16 }}
                    />
                )}
            </View>
        </Modal>

      </KeyboardAvoidingView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
  backButton: { flexDirection: 'row', alignItems: 'center' },
  backButtonText: { color: '#fff', fontSize: 16, marginLeft: 4 },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
  formContainer: { padding: 20 },
  label: { fontSize: 14, fontWeight: '600', color: '#475569', marginBottom: 8, marginTop: 12 },
  selector: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12, flexDirection: 'row', alignItems: 'center' },
  selectorText: { fontSize: 16, color: '#1e293b' },
  placeholderText: { fontSize: 16, color: '#94a3b8' },
  inputContainer: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8 },
  inputIcon: { marginLeft: 12 },
  input: { flex: 1, padding: 12, fontSize: 16, color: '#1e293b' },
  textArea: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, height: 100 },
  submitButton: { backgroundColor: '#246A73', padding: 16, borderRadius: 8, flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 30 },
  disabledButton: { backgroundColor: '#94a3b8' },
  submitButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
  modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
  modalHeader: { padding: 16, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
  modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
  modalItem: { padding: 16, backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#f1f5f9', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  modalItemText: { fontSize: 16, color: '#334155' }
});

export default AddAppraisalScreen;
