import React, { useState, useContext, useCallback } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, SafeAreaView, FlatList, ActivityIndicator, Linking } from 'react-native';
import { PlusCircle, Search, FileText, ExternalLink } from 'lucide-react-native';
import { useFocusEffect } from '@react-navigation/native';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const HomeScreen = ({ navigation }) => {
  const { userToken } = useContext(AuthContext);
  const [recentReports, setRecentReports] = useState([]);
  const [loading, setLoading] = useState(false);

  useFocusEffect(
    useCallback(() => {
      fetchRecentReports();
    }, [])
  );

  const fetchRecentReports = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${BASE_URL}/DefectReports/recent`, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      setRecentReports(response.data);
    } catch (error) {
      console.error('Error fetching recent reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const openReport = (url) => {
    if (url) {
      Linking.openURL(url).catch(err => console.error("Couldn't load page", err));
    }
  };

  const renderReportItem = ({ item }) => (
    <TouchableOpacity style={styles.reportItem} onPress={() => openReport(item.reportUrl)}>
      <View style={styles.reportIcon}>
        <FileText size={24} color="#246A73" />
      </View>
      <View style={styles.reportInfo}>
        <Text style={styles.reportTitle}>{item.reportName || 'Untitled Report'}</Text>
        <Text style={styles.reportMeta}>{item.artworkTitle} • {new Date(item.createdDate).toLocaleDateString()}</Text>
      </View>
      <ExternalLink size={16} color="#94a3b8" />
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Arteco Condition Reporting</Text>
        <Text style={styles.headerSubtitle}>Employee Portal</Text>
      </View>
      
      <View style={styles.content}>
        <TouchableOpacity 
          style={styles.card} 
          onPress={() => navigation.navigate('ReportTypeSelection')}
        >
          <View style={styles.iconContainer}>
            <PlusCircle size={40} color="#fff" />
          </View>
          <View style={styles.textContainer}>
            <Text style={styles.cardTitle}>Create New Condition Report</Text>
            <Text style={styles.cardDescription}>Start a new inspection for a customer artwork.</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity 
          style={styles.card} 
          onPress={() => navigation.navigate('RetrieveDefectReport')}
        >
          <View style={[styles.iconContainer, { backgroundColor: '#0ea5e9' }]}>
            <Search size={40} color="#fff" />
          </View>
          <View style={styles.textContainer}>
            <Text style={styles.cardTitle}>Retrieve a Condition Report</Text>
            <Text style={styles.cardDescription}>Search and view existing condition reports.</Text>
          </View>
        </TouchableOpacity>

        <View style={styles.recentSection}>
          <Text style={styles.sectionTitle}>Recent Reports</Text>
          {loading ? (
            <ActivityIndicator color="#246A73" style={{ marginTop: 20 }} />
          ) : (
            <FlatList
              data={recentReports}
              keyExtractor={(item) => item.defectReportId.toString()}
              renderItem={renderReportItem}
              ListEmptyComponent={<Text style={styles.emptyText}>No recent reports found.</Text>}
              showsVerticalScrollIndicator={false}
              contentContainerStyle={{ paddingBottom: 20 }}
            />
          )}
        </View>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  header: { padding: 20, backgroundColor: '#246A73', paddingBottom: 30 },
  headerTitle: { fontSize: 24, fontWeight: 'bold', color: '#fff' },
  headerSubtitle: { fontSize: 16, color: '#e2e8f0', marginTop: 5 },
  content: { flex: 1, padding: 20, marginTop: -20 },
  card: { 
    backgroundColor: 'white', 
    borderRadius: 12, 
    padding: 20, 
    marginBottom: 20, 
    flexDirection: 'row', 
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3
  },
  iconContainer: { 
    width: 60, 
    height: 60, 
    borderRadius: 30, 
    backgroundColor: '#246A73', 
    justifyContent: 'center', 
    alignItems: 'center',
    marginRight: 15
  },
  textContainer: { flex: 1 },
  cardTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b', marginBottom: 4 },
  cardDescription: { fontSize: 14, color: '#64748b' },
  
  recentSection: { flex: 1, marginTop: 10 },
  sectionTitle: { fontSize: 20, fontWeight: 'bold', color: '#1e293b', marginBottom: 15 },
  reportItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'white',
    padding: 15,
    borderRadius: 10,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: '#e2e8f0'
  },
  reportIcon: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#f0fdf4', // Light green bg
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12
  },
  reportInfo: { flex: 1 },
  reportTitle: { fontSize: 16, fontWeight: '600', color: '#333' },
  reportMeta: { fontSize: 12, color: '#64748b', marginTop: 2 },
  emptyText: { color: '#94a3b8', textAlign: 'center', marginTop: 20, fontStyle: 'italic' }
});

export default HomeScreen;