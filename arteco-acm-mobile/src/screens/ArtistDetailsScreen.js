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
  SafeAreaView,
  Dimensions
} from 'react-native';
import axios from 'axios';
import { useNavigation, useRoute } from '@react-navigation/native';
import { User, Globe, Frame, ChevronLeft, Upload } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const ArtistDetailsScreen = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const { id } = route.params; // Expecting { id: 123 } passed via navigation
  const { userToken, logout } = useContext(AuthContext);

  const [artist, setArtist] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchArtistDetails = async () => {
      if (!userToken) return;
      setLoading(true);
      try {
        const headers = { Authorization: `Bearer ${userToken}` };
        const res = await axios.get(`${BASE_URL}/artists/${id}`, { headers });
        setArtist(res.data);
      } catch (error) {
        console.error('Error fetching artist:', error);
        if (error.response?.status === 401) {
          Alert.alert('Session Expired', 'Please log in again.');
          logout();
        } else {
          Alert.alert('Error', 'Failed to load artist details.');
          navigation.goBack();
        }
      } finally {
        setLoading(false);
      }
    };

    fetchArtistDetails();
  }, [id, userToken, logout, navigation]);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#246A73" />
      </View>
    );
  }

  if (!artist) {
    return (
      <View style={styles.center}>
        <Text>Artist record not found.</Text>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
          <ChevronLeft size={24} color="#fff" />
          <Text style={styles.backButtonText}>Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Artist Profile</Text>
        <View style={{ width: 60 }} />
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Profile Image Section */}
        <View style={styles.imageSection}>
          <View style={styles.imageContainer}>
            {artist.profileImageUrl ? (
              <Image
                source={{ uri: artist.profileImageUrl }}
                style={styles.profileImage}
                resizeMode="cover"
              />
            ) : (
              <User size={80} color="#cbd5e1" />
            )}
          </View>
          <TouchableOpacity 
            style={styles.uploadButton}
            onPress={() => Alert.alert("Coming Soon", "Image upload functionality will be available in the next update.")}
          >
            <Upload size={16} color="#fff" />
            <Text style={styles.uploadButtonText}>Update Image</Text>
          </TouchableOpacity>
        </View>

        {/* Details Section */}
        <View style={styles.detailsSection}>
          <Text style={styles.artistName}>{artist.firstName} {artist.lastName}</Text>
          
          <View style={styles.metaRow}>
            <Globe size={16} color="#64748b" />
            <Text style={styles.nationality}>{artist.nationality || 'Nationality Unknown'}</Text>
          </View>

          <Text style={styles.biography}>
            {artist.biography || 'No biography available for this artist.'}
          </Text>
        </View>

        {/* Works in Collection */}
        <View style={styles.worksSection}>
          <View style={styles.sectionHeaderRow}>
            <Frame size={20} color="#1e293b" />
            <Text style={styles.sectionHeader}>Works in Collection</Text>
          </View>

          {artist.artworks && artist.artworks.length > 0 ? (
            artist.artworks.map((work) => (
               <TouchableOpacity
                key={work.artworkId}
                style={styles.artworkCard}
                onPress={() => navigation.navigate('ArtworkDetail', { id: work.artworkId })}
              >
                <View style={styles.artworkIcon}>
                  <Frame size={24} color="#64748b" />
                </View>
                <View style={styles.artworkInfo}>
                  <Text style={styles.artworkTitle}>{work.title}</Text>
                  <Text style={styles.artworkCost}>
                    £{work.acquisitionCost?.toLocaleString('en-GB') || '0.00'}
                  </Text>
                </View>
              </TouchableOpacity>
            ))
          ) : (
            <Text style={styles.emptyText}>No artworks linked to this artist.</Text>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
  backButton: { flexDirection: 'row', alignItems: 'center' },
  backButtonText: { color: '#fff', fontSize: 16, marginLeft: 4 },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
  scrollContent: { paddingBottom: 80 },
  imageSection: { alignItems: 'center', padding: 20, backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
  imageContainer: { width: 150, height: 150, borderRadius: 75, backgroundColor: '#f1f5f9', justifyContent: 'center', alignItems: 'center', overflow: 'hidden', borderWidth: 1, borderColor: '#e2e8f0', marginBottom: 15 },
  profileImage: { width: '100%', height: '100%' },
  uploadButton: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#246A73', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 20, gap: 8 },
  uploadButtonText: { color: '#fff', fontWeight: '600', fontSize: 14 },
  detailsSection: { padding: 20, backgroundColor: '#fff', marginTop: 10 },
  artistName: { fontSize: 24, fontWeight: 'bold', color: '#1e293b', marginBottom: 8, textAlign: 'center' },
  metaRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 20 },
  nationality: { fontSize: 16, color: '#64748b' },
  biography: { fontSize: 15, color: '#475569', lineHeight: 24, textAlign: 'justify' },
  worksSection: { padding: 20 },
  sectionHeaderRow: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 15 },
  sectionHeader: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
  artworkCard: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', padding: 15, borderRadius: 12, marginBottom: 10, shadowColor: '#000', shadowOffset: { width: 0, height: 1 }, shadowOpacity: 0.05, shadowRadius: 2, elevation: 1 },
  artworkIcon: { width: 40, height: 40, backgroundColor: '#f1f5f9', borderRadius: 8, justifyContent: 'center', alignItems: 'center', marginRight: 15 },
  artworkInfo: { flex: 1 },
  artworkTitle: { fontSize: 16, fontWeight: '600', color: '#1e293b' },
  artworkCost: { fontSize: 14, fontWeight: 'bold', color: '#059669', marginTop: 4 },
  emptyText: { color: '#94a3b8', fontStyle: 'italic', marginTop: 10 }
});

export default ArtistDetailsScreen;