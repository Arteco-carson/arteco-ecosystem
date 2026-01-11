import React, { useState, useEffect, useContext } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  FlatList,
  ActivityIndicator,
  SafeAreaView,
  KeyboardAvoidingView,
  Platform
} from 'react-native';
import axios from 'axios';
import { useNavigation } from '@react-navigation/native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const CreateCollectionScreen = () => {
  const navigation = useNavigation();
  const { userToken, logout } = useContext(AuthContext);
  const [loading, setLoading] = useState(false);
  const [collectionName, setCollectionName] = useState('');
  const [description, setDescription] = useState('');
  const [artworks, setArtworks] = useState([]);
  const [selectedArtworkIds, setSelectedArtworkIds] = useState([]);
  const [fetchingArtworks, setFetchingArtworks] = useState(true);

  // Fetch artworks on mount
  useEffect(() => {
    const fetchArtworks = async () => {
      try {
        if (!userToken) {
          logout();
          return;
        }
        
        const headers = { Authorization: `Bearer ${userToken}` };
        const res = await axios.get(`${BASE_URL}/artworks/user`, { headers });
        setArtworks(res.data);
      } catch (error) {
        console.error('Failed to fetch artworks:', error);
        Alert.alert('Error', 'Could not load artworks for selection.');
      } finally {
        setFetchingArtworks(false);
      }
    };

    fetchArtworks();
  }, [userToken, logout]);

  // Toggle selection for the "Transfer" list equivalent
  const toggleArtworkSelection = (id) => {
    setSelectedArtworkIds(prev => {
      if (prev.includes(id)) {
        return prev.filter(artworkId => artworkId !== id);
      } else {
        return [...prev, id];
      }
    });
  };

  const handleSubmit = async () => {
    if (!collectionName.trim()) {
      Alert.alert('Validation', 'Please input the collection name.');
      return;
    }

    setLoading(true);
    try {
      if (!userToken) {
        Alert.alert('Error', 'Session expired. Please log in again.');
        logout();
        return;
      }

      const headers = { Authorization: `Bearer ${userToken}` };
      const payload = {
        collectionName,
        description,
        artworkIds: selectedArtworkIds,
      };

      await axios.post(`${BASE_URL}/collections`, payload, { headers });
      
      Alert.alert('Success', 'Collection created successfully!', [
        { text: 'OK', onPress: () => navigation.goBack() }
      ]);
    } catch (error) {
      console.error('Failed to create collection:', error);
      if (error.response?.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', 'Failed to create collection. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const renderArtworkItem = ({ item }) => {
    const isSelected = selectedArtworkIds.includes(item.artworkId);
    return (
      <TouchableOpacity
        style={[styles.artworkItem, isSelected && styles.selectedArtworkItem]}
        onPress={() => toggleArtworkSelection(item.artworkId)}
      >
        <View style={styles.artworkInfo}>
          <Text style={styles.artworkTitle}>{item.title}</Text>
          <Text style={styles.artworkArtist}>{item.artistName}</Text>
        </View>
        {isSelected && (
          <View style={styles.checkmark}>
            <Text style={styles.checkmarkText}>✓</Text>
          </View>
        )}
      </TouchableOpacity>
    );
  };

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView 
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        style={styles.keyboardView}
      >
        {/* Header */}
        <View style={styles.header}>
          <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
            <Text style={styles.backButtonText}>Cancel</Text>
          </TouchableOpacity>
          <Text style={styles.headerTitle}>New Collection</Text>
          <View style={{ width: 50 }} /> 
        </View>

        <View style={styles.formContainer}>
          <Text style={styles.label}>Collection Name *</Text>
          <TextInput
            style={styles.input}
            placeholder="e.g., Modern Art"
            value={collectionName}
            onChangeText={setCollectionName}
            placeholderTextColor="#94a3b8"
          />

          <Text style={styles.label}>Description</Text>
          <TextInput
            style={[styles.input, styles.textArea]}
            placeholder="A brief description..."
            value={description}
            onChangeText={setDescription}
            multiline
            numberOfLines={3}
            placeholderTextColor="#94a3b8"
          />

          <View style={styles.listHeader}>
            <Text style={styles.label}>Select Artworks ({selectedArtworkIds.length})</Text>
            {/* Placeholder for Add Artwork Modal functionality */}
            <TouchableOpacity onPress={() => Alert.alert('Coming Soon', 'Add Artwork Modal will be implemented here.')}>
                <Text style={styles.addLink}>+ New Artwork</Text>
            </TouchableOpacity>
          </View>

          {fetchingArtworks ? (
            <ActivityIndicator size="small" color="#246A73" style={{ marginTop: 20 }} />
          ) : (
            <FlatList
              data={artworks}
              renderItem={renderArtworkItem}
              keyExtractor={item => item.artworkId.toString()}
              style={styles.list}
              contentContainerStyle={styles.listContent}
              ListEmptyComponent={<Text style={styles.emptyText}>No artworks available.</Text>}
            />
          )}
        </View>

        <View style={styles.footer}>
          <TouchableOpacity 
            style={[styles.createButton, loading && styles.disabledButton]} 
            onPress={handleSubmit}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.createButtonText}>Create Collection</Text>
            )}
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  keyboardView: { flex: 1 },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73', borderBottomWidth: 1, borderBottomColor: '#1e575f' },
  backButton: { padding: 5 },
  backButtonText: { color: '#e2e8f0', fontSize: 16 },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#ffffff' },
  formContainer: { flex: 1, padding: 16 },
  label: { fontSize: 14, fontWeight: '600', color: '#334155', marginBottom: 8, marginTop: 12 },
  input: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12, fontSize: 16, color: '#1e293b' },
  textArea: { height: 80, textAlignVertical: 'top' },
  listHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, marginBottom: 8 },
  addLink: { color: '#246A73', fontWeight: '600' },
  list: { flex: 1, backgroundColor: '#fff', borderRadius: 8, borderWidth: 1, borderColor: '#e2e8f0' },
  listContent: { padding: 0 },
  artworkItem: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 16, borderBottomWidth: 1, borderBottomColor: '#f1f5f9' },
  selectedArtworkItem: { backgroundColor: '#f0f9ff' },
  artworkInfo: { flex: 1 },
  artworkTitle: { fontSize: 16, color: '#1e293b', fontWeight: '500' },
  artworkArtist: { fontSize: 14, color: '#64748b', marginTop: 2 },
  checkmark: { marginLeft: 10 },
  checkmarkText: { color: '#246A73', fontSize: 18, fontWeight: 'bold' },
  emptyText: { padding: 20, textAlign: 'center', color: '#94a3b8' },
  footer: { padding: 16, backgroundColor: '#fff', borderTopWidth: 1, borderTopColor: '#e2e8f0' },
  createButton: { backgroundColor: '#246A73', paddingVertical: 14, borderRadius: 8, alignItems: 'center' },
  disabledButton: { backgroundColor: '#94a3b8' },
  createButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
});

export default CreateCollectionScreen;