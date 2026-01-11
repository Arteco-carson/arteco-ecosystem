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
  RefreshControl
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { History, Calendar, User, Plus, ChevronLeft } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const AppraisalListScreen = () => {
  const navigation = useNavigation();
  const { userToken, logout } = useContext(AuthContext);
  const [appraisals, setAppraisals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAppraisals = useCallback(async () => {
    if (!userToken) return;
    
    try {
      const response = await fetch(`${BASE_URL}/appraisals`, {
        headers: { 
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setAppraisals(data);
      } else if (response.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', 'Could not retrieve appraisal records.');
      }
    } catch (error) {
      console.error("Fetch Error:", error);
      Alert.alert('Connection Error', 'Management server is unreachable.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [userToken, logout]);

  useEffect(() => {
    fetchAppraisals();
  }, [fetchAppraisals]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchAppraisals();
  };

  const renderItem = ({ item }) => (
    <View style={styles.card}>
      <View style={styles.cardHeader}>
        <View style={styles.titleContainer}>
          <Text style={styles.artworkTitle} numberOfLines={1}>{item.artworkTitle}</Text>
          <Text style={styles.assetId}>Asset ID: #{item.artworkId}</Text>
        </View>
        <View style={styles.valueContainer}>
          <Text style={styles.valueText}>
            {item.currencyCode} {item.valuationAmount?.toLocaleString('en-GB', { minimumFractionDigits: 2 })}
          </Text>
        </View>
      </View>

      <View style={styles.divider} />

      <View style={styles.detailsRow}>
        <View style={styles.detailItem}>
          <User size={14} color="#64748b" />
          <Text style={styles.detailText}>{item.appraiserName}</Text>
        </View>
        <View style={styles.detailItem}>
          <Calendar size={14} color="#64748b" />
          <Text style={styles.detailText}>
            {new Date(item.valuationDate).toLocaleDateString('en-GB')}
          </Text>
        </View>
      </View>
    </View>
  );

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        {navigation.canGoBack() && (
          <TouchableOpacity onPress={() => navigation.goBack()} style={{ marginRight: 10 }}>
            <ChevronLeft size={24} color="#fff" />
          </TouchableOpacity>
        )}
        <View style={styles.headerTitleContainer}>
          <History size={24} color="#fff" />
          <Text style={styles.headerTitle}>Valuations</Text>
        </View>
        <TouchableOpacity 
          onPress={() => navigation.navigate('AddAppraisal')}
        >
          <Plus size={24} color="#fff" />
        </TouchableOpacity>
      </View>

      {loading && !refreshing ? (
        <View style={styles.center}>
          <ActivityIndicator size="large" color="#246A73" />
        </View>
      ) : (
        <FlatList
          data={appraisals}
          keyExtractor={item => item.appraisalId.toString()}
          renderItem={renderItem}
          contentContainerStyle={styles.listContent}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#246A73" />
          }
          ListEmptyComponent={
            <View style={styles.center}>
              <Text style={styles.emptyText}>No appraisal records found.</Text>
            </View>
          }
        />
      )}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73', borderBottomWidth: 1, borderBottomColor: '#1e575f' },
  headerTitleContainer: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#fff' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  listContent: { padding: 16, paddingBottom: 80 },
  card: { backgroundColor: 'white', borderRadius: 12, padding: 16, marginBottom: 12, shadowColor: '#000', shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.05, shadowRadius: 4, elevation: 2, borderWidth: 1, borderColor: '#e2e8f0' },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 },
  titleContainer: { flex: 1, marginRight: 10 },
  artworkTitle: { fontSize: 16, fontWeight: 'bold', color: '#1e293b', marginBottom: 4 },
  assetId: { fontSize: 12, color: '#3b82f6', fontWeight: '600' },
  valueContainer: { alignItems: 'flex-end' },
  valueText: { fontSize: 16, fontWeight: 'bold', color: '#059669' },
  divider: { height: 1, backgroundColor: '#f1f5f9', marginBottom: 12 },
  detailsRow: { flexDirection: 'row', justifyContent: 'space-between' },
  detailItem: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  detailText: { fontSize: 14, color: '#64748b' },
  emptyText: { color: '#94a3b8', fontSize: 16, textAlign: 'center' }
});

export default AppraisalListScreen;