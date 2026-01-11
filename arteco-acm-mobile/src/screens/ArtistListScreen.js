import React, { useState, useEffect, useContext, useCallback } from 'react';
import {
  View,
  Text,
  FlatList,
  Image,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  SafeAreaView,
  Alert
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import axios from 'axios';
import { User, Globe, Plus, ChevronRight, ChevronLeft } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const ArtistListScreen = () => {
  const navigation = useNavigation();
  const { userToken, logout } = useContext(AuthContext);
  const [artists, setArtists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failedImages, setFailedImages] = useState(new Set());

  const fetchArtists = useCallback(async () => {
    if (!userToken) return;
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${userToken}` };
      const res = await axios.get(`${BASE_URL}/artworks/user/artists`, { headers });
      setArtists(res.data);
    } catch (error) {
      console.error('Fetch Error:', error);
      if (error.response?.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', 'Failed to load artist registry.');
      }
    } finally {
      setLoading(false);
    }
  }, [userToken, logout]);

  useEffect(() => {
    fetchArtists();
  }, [fetchArtists]);

  const handleImageError = (artistId) => {
    setFailedImages(prev => {
      const newSet = new Set(prev);
      newSet.add(artistId);
      return newSet;
    });
  };

  const renderItem = ({ item }) => (
    <TouchableOpacity 
      style={styles.card}
      onPress={() => navigation.navigate('ArtistDetail', { id: item.artistId })}
    >
      <View style={styles.imageContainer}>
        {item.profileImageUrl && !failedImages.has(item.artistId) ? (
          <Image
            source={{ uri: item.profileImageUrl }}
            style={styles.image}
            onError={() => handleImageError(item.artistId)}
          />
        ) : (
          <View style={styles.placeholderImage}>
            <User size={24} color="#64748b" />
          </View>
        )}
      </View>
      
      <View style={styles.infoContainer}>
        <Text style={styles.name}>{item.firstName} {item.lastName}</Text>
        <View style={styles.nationalityRow}>
          <Globe size={14} color="#94a3b8" />
          <Text style={styles.nationality}>{item.nationality || 'Unknown'}</Text>
        </View>
      </View>

      <ChevronRight size={20} color="#cbd5e1" />
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <ChevronLeft size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Artists</Text>
        <TouchableOpacity onPress={() => Alert.alert('Coming Soon', 'Add Artist functionality will be implemented here.')}>
          <Plus size={24} color="#fff" />
        </TouchableOpacity>
      </View>

      {loading ? (
        <View style={styles.center}>
          <ActivityIndicator size="large" color="#246A73" />
        </View>
      ) : (
        <FlatList
          data={artists}
          renderItem={renderItem}
          keyExtractor={item => item.artistId.toString()}
          contentContainerStyle={styles.listContent}
          ListEmptyComponent={
            <View style={styles.center}>
              <Text style={styles.emptyText}>No artists currently registered.</Text>
            </View>
          }
        />
      )}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#fff' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  listContent: { padding: 16, paddingBottom: 80 },
  card: {
    backgroundColor: 'white', borderRadius: 12, padding: 16, marginBottom: 16,
    flexDirection: 'row', alignItems: 'center',
    shadowColor: '#000', shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.05, shadowRadius: 4, elevation: 2,
    borderWidth: 1, borderColor: '#f1f5f9'
  },
  imageContainer: { width: 50, height: 50, borderRadius: 10, overflow: 'hidden', marginRight: 16, backgroundColor: '#f1f5f9' },
  image: { width: '100%', height: '100%' },
  placeholderImage: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  infoContainer: { flex: 1 },
  name: { fontSize: 16, fontWeight: '600', color: '#1e293b', marginBottom: 4 },
  nationalityRow: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  nationality: { fontSize: 14, color: '#94a3b8' },
  emptyText: { color: '#64748b', fontSize: 16 }
});

export default ArtistListScreen;