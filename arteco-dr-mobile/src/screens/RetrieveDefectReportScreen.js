import React, { useState, useContext } from 'react';
import { View, Text, StyleSheet, SafeAreaView, TextInput, TouchableOpacity, FlatList, ActivityIndicator, Linking, Alert } from 'react-native';
import { Search, FileText, ExternalLink } from 'lucide-react-native';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const RetrieveDefectReportScreen = () => {
  const { userToken } = useContext(AuthContext);
  const [artworkName, setArtworkName] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);

  const handleSearch = async () => {
    setLoading(true);
    setHasSearched(true);
    try {
      const params = {};
      if (artworkName) params.artworkName = artworkName;
      if (fromDate) params.fromDate = fromDate;
      if (toDate) params.toDate = toDate;

      const response = await axios.get(`${BASE_URL}/DefectReports/search`, {
        headers: { Authorization: `Bearer ${userToken}` },
        params
      });
      setReports(response.data);
    } catch (error) {
      console.error('Search Error:', error);
      Alert.alert('Error', 'Failed to search reports.');
    } finally {
      setLoading(false);
    }
  };

  const openReport = (url) => {
    if (url) {
      Linking.openURL(url).catch(err => console.error("Couldn't load page", err));
    } else {
        Alert.alert('Info', 'No PDF URL available for this report.');
    }
  };

  const renderItem = ({ item }) => (
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
        <Text style={styles.headerTitle}>Search Reports</Text>
      </View>

      <View style={styles.filterContainer}>
        <Text style={styles.label}>Artwork Name</Text>
        <TextInput
            style={styles.input}
            placeholder="e.g. Mona Lisa"
            value={artworkName}
            onChangeText={setArtworkName}
        />

        <View style={styles.row}>
            <View style={styles.col}>
                <Text style={styles.label}>Date From (YYYY-MM-DD)</Text>
                <TextInput
                    style={styles.input}
                    placeholder="2023-01-01"
                    value={fromDate}
                    onChangeText={setFromDate}
                />
            </View>
            <View style={styles.col}>
                <Text style={styles.label}>Date To (YYYY-MM-DD)</Text>
                <TextInput
                    style={styles.input}
                    placeholder="2023-12-31"
                    value={toDate}
                    onChangeText={setToDate}
                />
            </View>
        </View>

        <TouchableOpacity style={styles.searchButton} onPress={handleSearch}>
            <Search color="#fff" size={20} style={{ marginRight: 10 }} />
            <Text style={styles.searchButtonText}>Search</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.resultsContainer}>
        {loading ? (
            <ActivityIndicator size="large" color="#246A73" style={{ marginTop: 20 }} />
        ) : (
            <FlatList
                data={reports}
                keyExtractor={(item) => item.defectReportId.toString()}
                renderItem={renderItem}
                ListEmptyComponent={
                    hasSearched ? <Text style={styles.emptyText}>No reports found matching criteria.</Text> : null
                }
                contentContainerStyle={{ paddingBottom: 20 }}
            />
        )}
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  header: { padding: 20, backgroundColor: '#246A73' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#fff' },
  filterContainer: { padding: 20, backgroundColor: '#fff', borderBottomWidth: 1, borderBottomColor: '#e2e8f0' },
  label: { fontSize: 14, fontWeight: '600', color: '#333', marginBottom: 5 },
  input: { backgroundColor: '#f8fafc', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 10, marginBottom: 15 },
  row: { flexDirection: 'row', justifyContent: 'space-between' },
  col: { width: '48%' },
  searchButton: { backgroundColor: '#246A73', flexDirection: 'row', justifyContent: 'center', alignItems: 'center', padding: 12, borderRadius: 8, marginTop: 5 },
  searchButtonText: { color: '#fff', fontWeight: 'bold', fontSize: 16 },
  resultsContainer: { flex: 1, padding: 20 },
  reportItem: { flexDirection: 'row', alignItems: 'center', backgroundColor: 'white', padding: 15, borderRadius: 10, marginBottom: 10, borderWidth: 1, borderColor: '#e2e8f0' },
  reportIcon: { width: 40, height: 40, borderRadius: 20, backgroundColor: '#f0fdf4', justifyContent: 'center', alignItems: 'center', marginRight: 12 },
  reportInfo: { flex: 1 },
  reportTitle: { fontSize: 16, fontWeight: '600', color: '#333' },
  reportMeta: { fontSize: 12, color: '#64748b', marginTop: 2 },
  emptyText: { textAlign: 'center', color: '#64748b', marginTop: 20, fontStyle: 'italic' }
});

export default RetrieveDefectReportScreen;