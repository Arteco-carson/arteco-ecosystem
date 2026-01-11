import React, { useState, useContext } from 'react';
import { View, Text, StyleSheet, TextInput, ScrollView, TouchableOpacity, Alert, ActivityIndicator } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { ChevronLeft } from 'lucide-react-native';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

export default function CreateNewObjectScreen({ navigation }) {
  const { userToken } = useContext(AuthContext);
  const [loading, setLoading] = useState(false);
  
  const [title, setTitle] = useState('');
  const [medium, setMedium] = useState('');
  const [height, setHeight] = useState('');
  const [width, setWidth] = useState('');
  const [depth, setDepth] = useState('');
  const [weight, setWeight] = useState('');
  const [lotNumber, setLotNumber] = useState('');
  const [provenance, setProvenance] = useState('');

  const handleNext = async () => {
    if (!title.trim()) {
      Alert.alert('Validation Error', 'Please enter a Title for the artwork.');
      return;
    }

    setLoading(true);
    try {
      const payload = {
        title,
        medium,
        heightCM: height ? parseFloat(height) : null,
        widthCM: width ? parseFloat(width) : null,
        depthCM: depth ? parseFloat(depth) : null,
        weightKG: weight ? parseFloat(weight) : null,
        lotNumber,
        provenanceText: provenance,
        status: 'In Storage'
      };

      const response = await axios.post(`${BASE_URL}/Artworks`, payload, {
        headers: { Authorization: `Bearer ${userToken}` }
      });

      const newArtwork = response.data;
      
      if (newArtwork && newArtwork.artworkId) {
        navigation.navigate('CaptureAndAnnotate', {
          artworkId: newArtwork.artworkId,
          artworkTitle: newArtwork.title,
          reportName: `Condition Report - ${newArtwork.title}`,
          customerId: newArtwork.createdByProfileId
        });
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Create Artwork Error:', error);
      Alert.alert('Error', 'Failed to save artwork details. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
          <ChevronLeft size={28} color="#fff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>New Object Details</Text>
        <View style={{ width: 28 }} />
      </View>

      <ScrollView contentContainerStyle={styles.form}>
        <Text style={styles.label}>Title *</Text>
        <TextInput style={styles.input} value={title} onChangeText={setTitle} placeholder="e.g. Untitled Composition" />

        <Text style={styles.label}>Medium</Text>
        <TextInput style={styles.input} value={medium} onChangeText={setMedium} placeholder="e.g. Oil on Canvas" />

        <View style={styles.row}>
            <View style={styles.col}>
                <Text style={styles.label}>Height (cm)</Text>
                <TextInput style={styles.input} value={height} onChangeText={setHeight} keyboardType="numeric" />
            </View>
            <View style={styles.col}>
                <Text style={styles.label}>Width (cm)</Text>
                <TextInput style={styles.input} value={width} onChangeText={setWidth} keyboardType="numeric" />
            </View>
            <View style={styles.col}>
                <Text style={styles.label}>Depth (cm)</Text>
                <TextInput style={styles.input} value={depth} onChangeText={setDepth} keyboardType="numeric" />
            </View>
        </View>

        <Text style={styles.label}>Weight (kg)</Text>
        <TextInput style={styles.input} value={weight} onChangeText={setWeight} keyboardType="numeric" />

        <Text style={styles.label}>Lot Number</Text>
        <TextInput style={styles.input} value={lotNumber} onChangeText={setLotNumber} />

        <Text style={styles.label}>Provenance / Notes</Text>
        <TextInput style={[styles.input, styles.textArea]} value={provenance} onChangeText={setProvenance} multiline numberOfLines={3} />

        <TouchableOpacity style={styles.button} onPress={handleNext} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Next: Capture Condition</Text>}
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  header: { padding: 15, backgroundColor: '#246A73', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
  backButton: { padding: 5 },
  form: { padding: 20 },
  label: { fontSize: 14, fontWeight: '600', color: '#333', marginBottom: 5, marginTop: 10 },
  input: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#ddd', borderRadius: 8, padding: 12, fontSize: 16 },
  textArea: { height: 80, textAlignVertical: 'top' },
  row: { flexDirection: 'row', justifyContent: 'space-between' },
  col: { width: '30%' },
  button: { backgroundColor: '#246A73', padding: 15, borderRadius: 10, alignItems: 'center', marginTop: 30 },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' }
});