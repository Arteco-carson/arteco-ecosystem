import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, SafeAreaView } from 'react-native';
import { ChevronLeft, FolderSearch, PackagePlus } from 'lucide-react-native';

const ReportTypeSelectionScreen = ({ navigation }) => {
  return (
    <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
          <ChevronLeft size={28} color="#fff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Select Report Type</Text>
        <View style={{ width: 28 }} />
      </View>

      <View style={styles.content}>
        <TouchableOpacity 
          style={styles.card} 
          onPress={() => navigation.navigate('CreateNewObject')}
        >
          <View style={[styles.iconContainer, { backgroundColor: '#8b5cf6' }]}>
            <PackagePlus size={40} color="#fff" />
          </View>
          <View style={styles.textContainer}>
            <Text style={styles.cardTitle}>New Object</Text>
            <Text style={styles.cardDescription}>Create a report for a new or uncatalogued item.</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity 
          style={styles.card} 
          onPress={() => navigation.navigate('CreateDefectReport')}
        >
          <View style={[styles.iconContainer, { backgroundColor: '#246A73' }]}>
            <FolderSearch size={40} color="#fff" />
          </View>
          <View style={styles.textContainer}>
            <Text style={styles.cardTitle}>Existing Asset</Text>
            <Text style={styles.cardDescription}>Select an existing artwork from the database.</Text>
          </View>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  header: {
    padding: 20,
    backgroundColor: '#246A73',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#fff' },
  backButton: { padding: 5 },
  content: { flex: 1, padding: 20 },
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
    justifyContent: 'center', 
    alignItems: 'center',
    marginRight: 15
  },
  textContainer: { flex: 1 },
  cardTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b', marginBottom: 4 },
  cardDescription: { fontSize: 14, color: '#64748b' }
});

export default ReportTypeSelectionScreen;