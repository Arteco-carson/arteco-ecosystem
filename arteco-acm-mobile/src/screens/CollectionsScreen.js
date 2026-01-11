import React, { useState, useEffect, useContext, useCallback } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  FlatList, 
  TouchableOpacity, 
  ActivityIndicator, 
  SafeAreaView, 
  Alert,
  Modal,
  Image
} from 'react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';
import { Layers, Trash2, Plus, Image as ImageIcon, X, CheckCircle } from 'lucide-react-native';

const CollectionsScreen = ({ navigation }) => {
  const { userToken } = useContext(AuthContext);
  const [collections, setCollections] = useState([]);
  const [artworks, setArtworks] = useState([]);
  const [selectedCollectionId, setSelectedCollectionId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingArtworks, setLoadingArtworks] = useState(false);

  // Add Artwork Modal State
  const [isAddModalVisible, setIsAddModalVisible] = useState(false);
  const [unassignedArtworks, setUnassignedArtworks] = useState([]);
  const [selectedArtworkIds, setSelectedArtworkIds] = useState([]);
  const [addingArtworks, setAddingArtworks] = useState(false);

  // --- 1. Fetch Collections ---
  const fetchCollections = useCallback(async () => {
    try {
      const response = await fetch(`${BASE_URL}/collections`, {
        headers: { 'Authorization': `Bearer ${userToken}` }
      });
      if (response.ok) {
        const data = await response.json();
        setCollections(data);
        
        // Default to first collection if none selected
        if (data.length > 0 && !selectedCollectionId) {
          setSelectedCollectionId(data[0].collectionId);
        } else if (data.length === 0) {
          setSelectedCollectionId(null);
          setArtworks([]);
        }
      }
    } catch (error) {
      console.error("Fetch Collections Error:", error);
      Alert.alert("Error", "Could not load collections.");
    } finally {
      setLoading(false);
    }
  }, [userToken, selectedCollectionId]);

  // --- 2. Fetch Artworks for Selected Collection ---
  const fetchArtworksForCollection = useCallback(async (id) => {
    if (!id) return;
    setLoadingArtworks(true);
    try {
      const response = await fetch(`${BASE_URL}/artworks/user?collectionId=${id}`, {
        headers: { 'Authorization': `Bearer ${userToken}` }
      });
      if (response.ok) {
        const data = await response.json();
        setArtworks(data);
      }
    } catch (error) {
      console.error("Fetch Artworks Error:", error);
    } finally {
      setLoadingArtworks(false);
    }
  }, [userToken]);

  // --- 3. Fetch Unassigned Artworks (For Modal) ---
  const fetchUnassignedArtworks = async () => {
    try {
      const response = await fetch(`${BASE_URL}/artworks/user?unassigned=true`, {
        headers: { 'Authorization': `Bearer ${userToken}` }
      });
      if (response.ok) {
        const data = await response.json();
        setUnassignedArtworks(data);
      }
    } catch (error) {
      Alert.alert("Error", "Could not load unassigned artworks.");
    }
  };

  // Initial Load
  useEffect(() => {
    fetchCollections();
  }, [fetchCollections]);

  // Load artworks when selection changes
  useEffect(() => {
    if (selectedCollectionId) {
      fetchArtworksForCollection(selectedCollectionId);
    }
  }, [selectedCollectionId, fetchArtworksForCollection]);

  // --- Handlers ---

  const handleDeleteCollection = () => {
    if (!selectedCollectionId) return;
    Alert.alert(
      "Delete Collection",
      "Are you sure? Artworks will be unassigned, not deleted.",
      [
        { text: "Cancel", style: "cancel" },
        { 
          text: "Delete", 
          style: "destructive", 
          onPress: async () => {
            try {
              await fetch(`${BASE_URL}/collections/${selectedCollectionId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${userToken}` }
              });
              // Refresh
              setSelectedCollectionId(null);
              fetchCollections();
            } catch (e) {
              Alert.alert("Error", "Failed to delete collection.");
            }
          }
        }
      ]
    );
  };

  const handleAddArtworks = async () => {
    if (selectedArtworkIds.length === 0) return;
    setAddingArtworks(true);
    try {
      await fetch(`${BASE_URL}/collections/${selectedCollectionId}/artworks`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(selectedArtworkIds)
      });
      setIsAddModalVisible(false);
      setSelectedArtworkIds([]);
      fetchArtworksForCollection(selectedCollectionId);
    } catch (error) {
      Alert.alert("Error", "Failed to add artworks.");
    } finally {
      setAddingArtworks(false);
    }
  };

  const toggleArtworkSelection = (id) => {
    setSelectedArtworkIds(prev => 
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  // --- Render Components ---

  const renderCollectionItem = ({ item }) => {
    const isSelected = item.collectionId === selectedCollectionId;
    return (
      <TouchableOpacity 
        style={[styles.chip, isSelected && styles.chipSelected]}
        onPress={() => setSelectedCollectionId(item.collectionId)}
      >
        <Text style={[styles.chipText, isSelected && styles.chipTextSelected]}>
          {item.collectionName}
        </Text>
      </TouchableOpacity>
    );
  };

  const renderArtworkItem = ({ item }) => (
    <TouchableOpacity 
      style={styles.card}
      onPress={() => navigation.navigate('ArtworkDetail', { id: item.artworkId })}
    >
      <View style={styles.imageContainer}>
        {item.imageUrl ? (
          <Image source={{ uri: item.imageUrl }} style={styles.image} resizeMode="cover" />
        ) : (
          <ImageIcon color="#cbd5e1" size={40} />
        )}
      </View>
      <View style={styles.cardInfo}>
        <Text style={styles.cardTitle} numberOfLines={1}>{item.title}</Text>
        <Text style={styles.cardPrice}>
          £{item.acquisitionCost?.toLocaleString('en-GB')}
        </Text>
      </View>
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Collections</Text>
        <TouchableOpacity onPress={() => navigation.navigate('CreateCollection')}>
          <Plus color="#ffffff" size={24} />
        </TouchableOpacity>
      </View>

      {/* Collection Selector */}
      <View style={styles.selectorContainer}>
        {loading ? (
          <ActivityIndicator color="#246A73" />
        ) : (
          <FlatList
            data={collections}
            horizontal
            showsHorizontalScrollIndicator={false}
            keyExtractor={item => item.collectionId.toString()}
            renderItem={renderCollectionItem}
            contentContainerStyle={{ paddingHorizontal: 15 }}
          />
        )}
      </View>

      {/* Toolbar */}
      {selectedCollectionId && (
        <View style={styles.toolbar}>
          <TouchableOpacity style={styles.toolButton} onPress={handleDeleteCollection}>
            <Trash2 color="#ef4444" size={18} />
            <Text style={[styles.toolText, { color: '#ef4444' }]}>Delete</Text>
          </TouchableOpacity>
          
          <TouchableOpacity 
            style={styles.toolButton} 
            onPress={() => {
              fetchUnassignedArtworks();
              setIsAddModalVisible(true);
            }}
          >
            <Layers color="#246A73" size={18} />
            <Text style={styles.toolText}>Add Artwork</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Main Content */}
      {loadingArtworks ? (
        <View style={styles.center}>
          <ActivityIndicator size="large" color="#246A73" />
        </View>
      ) : (
        <FlatList
          data={artworks}
          keyExtractor={item => item.artworkId.toString()}
          renderItem={renderArtworkItem}
          numColumns={2}
          contentContainerStyle={styles.gridContent}
          ListEmptyComponent={
            <Text style={styles.emptyText}>No artworks in this collection.</Text>
          }
        />
      )}

      {/* Add Artwork Modal */}
      <Modal
        visible={isAddModalVisible}
        animationType="slide"
        presentationStyle="pageSheet"
      >
        <View style={styles.modalContainer}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Add to Collection</Text>
            <TouchableOpacity onPress={() => setIsAddModalVisible(false)}>
              <X color="#1e293b" size={24} />
            </TouchableOpacity>
          </View>
          
          <FlatList
            data={unassignedArtworks}
            keyExtractor={item => item.artworkId.toString()}
            contentContainerStyle={{ padding: 20 }}
            renderItem={({ item }) => {
              const isSelected = selectedArtworkIds.includes(item.artworkId);
              return (
                <TouchableOpacity 
                  style={[styles.modalItem, isSelected && styles.modalItemSelected]}
                  onPress={() => toggleArtworkSelection(item.artworkId)}
                >
                  <Text style={styles.modalItemText}>{item.title}</Text>
                  {isSelected && <CheckCircle color="#246A73" size={20} />}
                </TouchableOpacity>
              );
            }}
            ListEmptyComponent={<Text style={styles.emptyText}>No unassigned artworks found.</Text>}
          />

          <View style={styles.modalFooter}>
            <TouchableOpacity 
              style={[styles.modalButton, selectedArtworkIds.length === 0 && styles.disabledButton]}
              disabled={selectedArtworkIds.length === 0 || addingArtworks}
              onPress={handleAddArtworks}
            >
              {addingArtworks ? <ActivityIndicator color="white" /> : <Text style={styles.modalButtonText}>Add Selected</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20, backgroundColor: '#246A73', borderBottomWidth: 1, borderColor: '#1e575f' },
  headerTitle: { fontSize: 22, fontWeight: 'bold', color: '#ffffff' },
  selectorContainer: { paddingVertical: 15, backgroundColor: 'white' },
  chip: { paddingHorizontal: 16, paddingVertical: 8, borderRadius: 20, backgroundColor: '#f1f5f9', marginRight: 10, borderWidth: 1, borderColor: '#e2e8f0' },
  chipSelected: { backgroundColor: '#246A73', borderColor: '#246A73' },
  chipText: { color: '#64748b', fontWeight: '600' },
  chipTextSelected: { color: 'white' },
  toolbar: { flexDirection: 'row', justifyContent: 'flex-end', paddingHorizontal: 20, paddingBottom: 10, backgroundColor: 'white', gap: 15 },
  toolButton: { flexDirection: 'row', alignItems: 'center', gap: 5 },
  toolText: { fontSize: 14, fontWeight: '600', color: '#246A73' },
  gridContent: { padding: 10, paddingBottom: 80 },
  card: { flex: 1, backgroundColor: 'white', margin: 8, borderRadius: 12, overflow: 'hidden', elevation: 2, shadowColor: '#000', shadowOpacity: 0.05, shadowRadius: 5 },
  imageContainer: { height: 140, backgroundColor: '#f1f5f9', alignItems: 'center', justifyContent: 'center' },
  image: { width: '100%', height: '100%' },
  cardInfo: { padding: 10 },
  cardTitle: { fontSize: 14, fontWeight: 'bold', color: '#1e293b', marginBottom: 4 },
  cardPrice: { fontSize: 13, color: '#059669', fontWeight: '600' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  emptyText: { textAlign: 'center', marginTop: 40, color: '#94a3b8' },
  modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
  modalHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20, backgroundColor: 'white', borderBottomWidth: 1, borderColor: '#e2e8f0' },
  modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
  modalItem: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 15, backgroundColor: 'white', borderRadius: 8, marginBottom: 10, borderWidth: 1, borderColor: '#e2e8f0' },
  modalItemSelected: { borderColor: '#246A73', backgroundColor: '#f0fdfa' },
  modalItemText: { fontSize: 16, color: '#334155' },
  modalFooter: { padding: 20, backgroundColor: 'white', borderTopWidth: 1, borderColor: '#e2e8f0' },
  modalButton: { backgroundColor: '#246A73', padding: 15, borderRadius: 8, alignItems: 'center' },
  disabledButton: { backgroundColor: '#94a3b8' },
  modalButtonText: { color: 'white', fontWeight: 'bold', fontSize: 16 }
});

export default CollectionsScreen;