import React, { useState, useEffect, useContext } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  FlatList, 
  TouchableOpacity, 
  ActivityIndicator, 
  SafeAreaView,
  RefreshControl,
  Image,
  Alert
} from 'react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';
import { Image as ImageIcon, ChevronRight, AlertCircle, Plus } from 'lucide-react-native';
import AddArtworkModalScreen from './AddArtworkModalScreen';

const ArtworkListScreen = ({ navigation }) => {
  const { userToken, signOut } = useContext(AuthContext);
  const [artworks, setArtworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [isAddModalVisible, setIsAddModalVisible] = useState(false);

  const fetchArtworks = async () => {
    try {
      const response = await fetch(`${BASE_URL}/artworks`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setArtworks(data);
        setError(null);
      } else if (response.status === 401) {
        signOut(); // Force login if token expired (ISO27001 requirement)
      } else {
        setError('Unable to sync with UK management database.');
      }
    } catch (err) {
      setError('Connection Error: Backend API is unreachable.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchArtworks();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchArtworks();
  };

  const renderItem = ({ item }) => (
    <TouchableOpacity 
      style={styles.artworkCard}
      onPress={() => navigation.navigate('ArtworkDetail', { id: item.artworkId })}
    >
      <View style={styles.imagePlaceholder}>
        {item.imageUrl || item.blobUrl ? (
          <Image 
            source={{ uri: item.imageUrl || item.blobUrl }} 
            style={styles.image} 
            resizeMode="cover" 
          />
        ) : (
          <ImageIcon color="#94a3b8" size={30} />
        )}
      </View>
      
      <View style={styles.infoContainer}>
        <Text style={styles.artworkTitle} numberOfLines={1}>{item.title}</Text>
        <Text style={styles.artistName}>Managed Asset ID: {item.artworkId}</Text>
        <Text style={styles.priceText}>
          {new Intl.NumberFormat('en-GB', {
            style: 'currency',
            currency: 'GBP',
          }).format(item.acquisitionCost || 0)}
        </Text>
      </View>

      <ChevronRight color="#cbd5e1" size={20} />
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      {/* HEADER SECTION */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Fine Art Inventory</Text>
        <TouchableOpacity 
          style={styles.addButton}
          onPress={() => setIsAddModalVisible(true)}
        >
          <Plus color="#fff" size={20} />
        </TouchableOpacity>
      </View>

      {error && (
        <View style={styles.errorBanner}>
          <AlertCircle color="#991b1b" size={18} />
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      {loading && !refreshing ? (
        <View style={styles.center}>
          <ActivityIndicator size="large" color="#2c3e50" />
        </View>
      ) : (
        <FlatList
          data={artworks}
          keyExtractor={(item) => item.artworkId.toString()}
          renderItem={renderItem}
          contentContainerStyle={styles.listContent}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#2c3e50" />
          }
          ListEmptyComponent={
            <Text style={styles.emptyText}>No assets found in the current registry.</Text>
          }
        />
      )}

      <AddArtworkModalScreen 
        visible={isAddModalVisible} 
        onClose={() => setIsAddModalVisible(false)}
        onArtworkCreated={fetchArtworks}
      />
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20, backgroundColor: '#246A73', borderBottomWidth: 1, borderBottomColor: '#1e575f' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#ffffff' },
  addButton: { backgroundColor: '#2563eb', padding: 8, borderRadius: 8 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  listContent: { padding: 15 },
  artworkCard: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', padding: 15, borderRadius: 12, marginBottom: 12, shadowColor: '#000', shadowOffset: { width: 0, height: 1 }, shadowOpacity: 0.05, shadowRadius: 5, elevation: 2 },
  imagePlaceholder: { width: 60, height: 60, backgroundColor: '#f1f5f9', borderRadius: 8, alignItems: 'center', justifyContent: 'center', marginRight: 15, overflow: 'hidden' },
  image: { width: '100%', height: '100%' },
  infoContainer: { flex: 1 },
  artworkTitle: { fontSize: 16, fontWeight: 'bold', color: '#1e293b' },
  artistName: { fontSize: 13, color: '#64748b', marginTop: 2 },
  priceText: { fontSize: 15, fontWeight: '600', color: '#059669', marginTop: 4 },
  errorBanner: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fef2f2', padding: 12, margin: 15, borderRadius: 8, gap: 8, borderWidth: 1, borderColor: '#fee2e2' },
  errorText: { color: '#991b1b', fontSize: 13, fontWeight: '500' },
  emptyText: { textAlign: 'center', marginTop: 50, color: '#94a3b8' }
});

export default ArtworkListScreen;