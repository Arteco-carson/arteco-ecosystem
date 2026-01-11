import 'react-native-gesture-handler';
import React, { useState, useContext } from 'react';
import { View, Text, StyleSheet, Button, Image, Alert, TextInput, Modal, ScrollView, TouchableOpacity, Linking, Platform, ActivityIndicator } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as ImagePicker from 'expo-image-picker';
import * as Print from 'expo-print';
import * as FileSystem from 'expo-file-system';
import { ConditionPointerAnnotator } from '../components/ConditionPointerAnnotator';
import { ChevronLeft, Square, Circle, ArrowUpRight, Plus } from 'lucide-react-native';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

export default function CaptureAndAnnotateScreen({ route, navigation }) {
  const { reportName, artworkId, customerId, artworkTitle } = route.params;
  const { userToken, logout } = useContext(AuthContext);
  const [images, setImages] = useState([]);
  const [currentImageIndex, setCurrentImageIndex] = useState(-1);
  const [isAnnotating, setIsAnnotating] = useState(false);
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [previewLayout, setPreviewLayout] = useState(null);
  const [editingNote, setEditingNote] = useState(null);
  const [noteModalVisible, setNoteModalVisible] = useState(false);

  // Ensure we have a report name even if navigation params didn't provide one
  const effectiveReportName = reportName || (artworkTitle ? `Condition Report - ${artworkTitle}` : `Condition Report - ${new Date().toLocaleDateString()}`);

  const takePicture = async () => {
    console.log('Take Photo button pressed');
    try {
      // 1. Request permissions
      console.log('Requesting camera permissions...');
      const permissionResult = await ImagePicker.requestCameraPermissionsAsync();
      console.log('Permission status:', permissionResult.status);
      if (permissionResult.status !== 'granted') {
        Alert.alert(
          'Permission Required',
          'Camera permission is required to take photos. Please enable it in app settings.',
          [
            { text: 'Cancel', style: 'cancel' },
            { text: 'Open Settings', onPress: () => Linking.openSettings() }
          ]
        );
        return;
      }

      // 2. Launch Camera
      console.log('Launching camera...');
      const result = await ImagePicker.launchCameraAsync({
        mediaTypes: ImagePicker.MediaTypeOptions.Images,
        allowsEditing: false,
        quality: 1,
      });
      console.log('Camera result:', result.canceled ? 'Canceled' : 'Captured');

      // 3. Save URI if not canceled
      if (!result.canceled && result.assets && result.assets.length > 0) {
        const newImage = { uri: result.assets[0].uri, annotations: [] };
        setImages(prev => {
          const newState = [...prev, newImage];
          setCurrentImageIndex(newState.length - 1);
          return newState;
        });
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred while taking the photo: ' + (error.message || error));
      console.error(error);
    }
  };

  const handleSaveAnnotations = (paths, width, height) => {
    setImages(prev => {
      const newState = [...prev];
      if (currentImageIndex >= 0 && currentImageIndex < newState.length) {
        newState[currentImageIndex] = { 
          ...newState[currentImageIndex], 
          annotations: paths,
          annotationDims: { width, height }
        };
      }
      return newState;
    });
    setIsAnnotating(false);
  };

  const removeCurrentImage = () => {
    if (currentImageIndex === -1) return;
    
    setImages(prev => {
      const newState = prev.filter((_, i) => i !== currentImageIndex);
      if (newState.length === 0) {
        setCurrentImageIndex(-1);
      } else if (currentImageIndex >= newState.length) {
        setCurrentImageIndex(newState.length - 1);
      }
      return newState;
    });
  };
  
  const handleSaveReport = async () => {
    if (images.length === 0) {
      Alert.alert('Required', 'Please take at least one photo of the defect.');
      return;
    }

    setSaving(true);
    try {
      // Step 1: Upload all images first
      const uploadedImages = [];
      for (let i = 0; i < images.length; i++) {
        const img = images[i];
        const formData = new FormData();
        const fileName = `defect_${artworkId}_${Date.now()}_${i}.jpg`;
        formData.append('files', {
          uri: Platform.OS === 'ios' ? img.uri.replace('file://', '') : img.uri,
          type: 'image/jpeg',
          name: fileName,
        });

        const uploadRes = await axios.post(`${BASE_URL}/DefectImages/upload`, formData, {
          headers: {
            'Authorization': `Bearer ${userToken}`,
            'Content-Type': 'multipart/form-data',
          },
        });

        if (uploadRes.data?.imageUrls?.[0]) {
          uploadedImages.push({
            url: uploadRes.data.imageUrls[0],
            annotations: img.annotations
          });
        }
      }

      if (uploadedImages.length === 0) {
        throw new Error('Failed to upload any images.');
      }

      // Step 2: Generate PDF Report
      // Pre-convert images to Base64 to ensure they render in the PDF on Android
      const base64Images = await Promise.all(images.map(async (img) => {
        try {
          const base64 = await FileSystem.readAsStringAsync(img.uri, { encoding: FileSystem.EncodingType.Base64 });
          return `data:image/jpeg;base64,${base64}`;
        } catch (e) {
          console.warn('Base64 conversion failed', e);
          return img.uri; // Fallback
        }
      }));

      const htmlContent = `
        <html>
          <head>
            <style>
              body { font-family: Helvetica, Arial, sans-serif; padding: 20px; }
              h1 { color: #246A73; margin-bottom: 10px; }
              .meta { margin-bottom: 20px; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
              .notes { background: #f0f2f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
              .image-row { display: flex; flex-direction: row; margin-bottom: 30px; page-break-inside: avoid; border-bottom: 1px solid #eee; padding-bottom: 20px; }
              .image-col { width: 40%; margin-right: 5%; }
              .text-col { width: 55%; }
              .img-wrapper { position: relative; width: 100%; border: 1px solid #eee; }
              img { width: 100%; display: block; }
              .footer { margin-top: 30px; font-size: 12px; color: #888; text-align: center; }
            </style>
          </head>
          <body>
            <h1>Condition Report</h1>
            <div class="meta">
              <p><strong>Report Name:</strong> ${effectiveReportName}</p>
              <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
              <p><strong>Artwork Name:</strong> ${artworkTitle || ''}</p>
            </div>
            
            <div class="notes">
              <h3>Notes</h3>
              <p>${notes || 'No notes provided.'}</p>
            </div>
            
            <h3>Attached Images</h3>
            ${images.map((img, index) => {
              const dims = img.annotationDims;
              let overlays = '';
              
              if (img.annotations && img.annotations.length > 0 && dims) {
                 overlays = img.annotations.map(ann => {
                    const left = (ann.x / dims.width) * 100;
                    const top = (ann.y / dims.height) * 100;
                    const width = (ann.width / dims.width) * 100;
                    const rawHeight = ann.type === 'Arrow' ? 80 : ann.height;
                    const height = (rawHeight / dims.height) * 100;
                    const rotation = ann.rotation || 0;
                    
                    let inner = '';
                    if (ann.type === 'Rectangle') {
                        inner = `<div style="width:100%; height:100%; border:3px solid #FF3B30; background-color:rgba(255,59,48,0.2);"></div>`;
                    } else if (ann.type === 'Circle') {
                        inner = `<div style="width:100%; height:100%; border:3px solid #FF3B30; background-color:rgba(255,59,48,0.2); border-radius:50%;"></div>`;
                    } else if (ann.type === 'Arrow') {
                        inner = `<svg viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="#FF3B30" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="7" y1="17" x2="17" y2="7"></line><polyline points="7 7 17 7 17 17"></polyline></svg>`;
                    }
                    
                    return `<div style="position:absolute; left:${left}%; top:${top}%; width:${width}%; height:${height}%; transform:rotate(${rotation}deg); pointer-events:none;">${inner}</div>`;
                 }).join('');
              }

              return `
              <div class="image-row">
                <div class="image-col">
                    <div class="img-wrapper">
                        <img src="${base64Images[index]}" />
                        ${overlays}
                    </div>
                    <p style="text-align: center; font-size: 0.9em; color: #666;">Image ${index + 1}</p>
                </div>
                <div class="text-col">
                    ${img.annotations && img.annotations.length > 0 ? `
                      <div>
                        <strong>Condition Points:</strong>
                        <ul style="margin-top: 5px; padding-left: 20px;">
                          ${img.annotations.map(a => `
                            <li style="margin-bottom: 5px;"><strong>${a.type}:</strong> ${a.text || 'No description'}</li>
                          `).join('')}
                        </ul>
                      </div>
                    ` : '<p>No specific condition points marked.</p>'}
                </div>
              </div>
            `;
            }).join('')}
            
            <div class="footer">Generated by Arteco Condition Reporting Tool</div>
          </body>
        </html>
      `;

      const { uri: pdfUri } = await Print.printToFileAsync({ html: htmlContent });

      // Step 3: Upload PDF
      const pdfFormData = new FormData();
      const pdfFileName = `Report_${artworkId}_${Date.now()}.pdf`;
      
      pdfFormData.append('file', {
        uri: Platform.OS === 'ios' ? pdfUri.replace('file://', '') : pdfUri,
        type: 'application/pdf',
        name: pdfFileName,
      });

      const pdfUploadRes = await axios.post(`${BASE_URL}/DefectReports/upload`, pdfFormData, {
        headers: {
          'Authorization': `Bearer ${userToken}`,
          'Content-Type': 'multipart/form-data',
        },
      });

      const pdfUrl = pdfUploadRes.data?.url;
      if (!pdfUrl) {
        throw new Error('Failed to upload PDF report.');
      }

      // Step 4: Create the main Defect Report
      const reportPayload = {
        artworkId,
        reportName: effectiveReportName,
        reportUrl: pdfUrl, // Save the PDF URL here
        aiSummary: notes, // Using AISummary for user notes for now.
        status: 'Open',
      };

      const reportRes = await axios.post(`${BASE_URL}/DefectReports`, reportPayload, {
        headers: { Authorization: `Bearer ${userToken}` },
      });

      // Assuming the API returns the created report with its ID, e.g., { ..., defectReportId: 123 }
      const defectReportId = reportRes.data.defectReportId;
      if (!defectReportId) {
        throw new Error('API did not return a defectReportId after creation.');
      }

      // Step 5: Create DefectImage records
      for (const img of uploadedImages) {
        const defectImagePayload = {
          defectReportId,
          rawImageUrl: img.url,
          annotatedImageUrl: null,
          annotationMetadata: JSON.stringify(img.annotations),
        };

        await axios.post(`${BASE_URL}/DefectImages`, defectImagePayload, {
          headers: { Authorization: `Bearer ${userToken}` },
        });
      }

      Alert.alert('Success', 'Defect report saved successfully.', [
        { text: 'OK', onPress: () => navigation.navigate('Home', { screen: 'HomeScreenContent' }) },
      ]);
    } catch (error) {
      console.error('Save Report Error:', error);
      // More specific error message for the user
      let errorMessage = error.message || 'An unknown error occurred.';
      if (error.response?.data) {
          // Handle both object with message property and raw string response
          errorMessage = typeof error.response.data === 'string' ? error.response.data : (error.response.data.message || errorMessage);
      }
      
      if (error.response?.status === 401) {
        Alert.alert('Session Expired', 'Please log in again.');
        logout();
      } else {
        Alert.alert('Error', `Failed to save report: ${errorMessage}`);
      }
    } finally {
      setSaving(false);
    }
  };

  const currentImage = currentImageIndex >= 0 ? images[currentImageIndex] : null;

  const handleUpdateNote = () => {
    if (!editingNote) return;
    
    setImages(prev => {
      const newState = [...prev];
      if (currentImageIndex >= 0 && currentImageIndex < newState.length) {
        const currentImg = newState[currentImageIndex];
        const updatedAnnotations = currentImg.annotations.map(ann => 
            ann.id === editingNote.id ? { ...ann, text: editingNote.text } : ann
        );
        newState[currentImageIndex] = { ...currentImg, annotations: updatedAnnotations };
      }
      return newState;
    });
    setNoteModalVisible(false);
    setEditingNote(null);
  };

  const renderOverlay = () => {
    if (!currentImage?.annotations || !currentImage.annotationDims || !previewLayout) return null;
    
    const { width: origW, height: origH } = currentImage.annotationDims;
    const { width: targetW, height: targetH } = previewLayout;
    
    if (!origW || !origH) return null;

    const scaleX = targetW / origW;
    const scaleY = targetH / origH;

    return currentImage.annotations.map(ann => {
        const annW = ann.width * scaleX;
        const annH = (ann.type === 'Arrow' ? 80 : ann.height) * scaleY;
        const annX = ann.x * scaleX;
        const annY = ann.y * scaleY;
        const rotation = ann.rotation || 0;

        return (
            <TouchableOpacity 
              key={ann.id} 
              onPress={() => {
                setEditingNote({ id: ann.id, text: ann.text || '' });
                setNoteModalVisible(true);
              }}
              style={{
                position: 'absolute',
                left: annX,
                top: annY,
                width: annW,
                height: annH,
                transform: [{ rotate: `${rotation}deg` }],
                alignItems: 'center',
                justifyContent: 'center',
            }}>
                {ann.type === 'Rectangle' && (
                    <View style={{ width: '100%', height: '100%', borderWidth: 3 * scaleX, borderColor: '#FF3B30', backgroundColor: 'rgba(255, 59, 48, 0.2)' }} />
                )}
                {ann.type === 'Circle' && (
                    <View style={{ width: '100%', height: '100%', borderRadius: 999, borderWidth: 3 * scaleX, borderColor: '#FF3B30', backgroundColor: 'rgba(255, 59, 48, 0.2)' }} />
                )}
                {ann.type === 'Arrow' && (
                    <ArrowUpRight size={60 * Math.min(scaleX, scaleY)} color="#FF3B30" strokeWidth={3} />
                )}
            </TouchableOpacity>
        );
    });
  };

  return (
    <SafeAreaView style={styles.safeArea} edges={['top', 'left', 'right']}>
    <View style={styles.header}>
      <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
        <ChevronLeft size={28} color="#fff" />
      </TouchableOpacity>
      <Text style={styles.headerTitle} numberOfLines={1}>{reportName}</Text>
      <View style={{ width: 38 }} />
    </View>
    <ScrollView contentContainerStyle={styles.container}>
      
      <View style={styles.previewContainer} onLayout={(e) => setPreviewLayout(e.nativeEvent.layout)}>
        {currentImage ? (
          <View style={{ flex: 1, width: '100%', height: '100%' }}>
            <Image source={{ uri: currentImage.uri }} style={styles.preview} />
            {renderOverlay()}
          </View>
        ) : (
          <View style={styles.placeholder}>
            <Text style={styles.placeholderText}>No image captured</Text>
          </View>
        )}
      </View>

      {images.length > 0 && (
        <ScrollView horizontal style={styles.thumbnailList} contentContainerStyle={styles.thumbnailContent}>
          {images.map((img, index) => (
            <TouchableOpacity 
              key={index} 
              onPress={() => setCurrentImageIndex(index)}
              style={[
                styles.thumbnailItem, 
                currentImageIndex === index && styles.thumbnailSelected
              ]}
            >
              <Image source={{ uri: img.uri }} style={styles.thumbnailImage} />
            </TouchableOpacity>
          ))}
          <TouchableOpacity 
            onPress={takePicture}
            style={[
              styles.thumbnailItem, 
              { justifyContent: 'center', alignItems: 'center', backgroundColor: '#f1f5f9', borderColor: '#cbd5e1', borderStyle: 'dashed', borderWidth: 1 }
            ]}
          >
            <Plus size={24} color="#64748b" />
          </TouchableOpacity>
        </ScrollView>
      )}

      {currentImage && (
        <View style={styles.formContainer}>
          <View style={styles.imageActions}>
            <Button 
              title={currentImage.annotations.length > 0 ? "Edit Highlights" : "Highlight Defects"} 
              onPress={() => setIsAnnotating(true)} 
              color="#007AFF"
            />
            <View style={{ width: 10 }} />
            <Button title="Remove" onPress={removeCurrentImage} color="#FF3B30" />
          </View>
          
          {currentImage.annotations && currentImage.annotations.length > 0 && (
            <View style={styles.tableContainer}>
              <View style={styles.tableHeader}>
                <Text style={[styles.tableHeaderText, styles.colType]}>Type</Text>
                <Text style={[styles.tableHeaderText, styles.colNote]}>Note</Text>
              </View>
              {currentImage.annotations.map((ann, i) => (
                <View key={i} style={styles.tableRow}>
                  <Text style={styles.colType}>{ann.type}</Text>
                  <Text style={styles.colNote}>{ann.text || '-'}</Text>
                </View>
              ))}
            </View>
          )}

          <Text style={styles.label}>Defect Notes</Text>
          <TextInput
            style={styles.input}
            placeholder="Describe the issue here..."
            value={notes}
            onChangeText={setNotes}
            multiline
            numberOfLines={4}
          />
        </View>
      )}

      <View style={styles.controls}>
        <Button 
          title={images.length > 0 ? "Add Another Photo" : "Take Photo"}
          onPress={takePicture} 
          color="#007AFF"
        />
        {images.length > 0 && (
            <View style={styles.saveButton}>
                {saving ? (
                  <ActivityIndicator size="large" color="#34C759" />
                ) : (
                  <Button 
                    title="Save Report" 
                    onPress={handleSaveReport} 
                    color="#34C759"
                  />
                )}
            </View>
        )}
      </View>

      <Modal visible={isAnnotating} animationType="slide" onRequestClose={() => setIsAnnotating(false)}>
        <ConditionPointerAnnotator 
          imageUrl={currentImage?.uri} 
          initialPaths={currentImage?.annotations || []}
          onSave={handleSaveAnnotations}
          onCancel={() => setIsAnnotating(false)}
        />
      </Modal>

      <Modal visible={noteModalVisible} transparent animationType="fade" onRequestClose={() => setNoteModalVisible(false)}>
        <View style={styles.modalOverlay}>
            <View style={styles.modalContent}>
                <Text style={styles.modalTitle}>Edit Note</Text>
                <TextInput
                    style={styles.modalInput}
                    value={editingNote?.text || ''}
                    onChangeText={(text) => setEditingNote(prev => ({ ...prev, text }))}
                    placeholder="Describe the condition..."
                    autoFocus
                />
                <View style={styles.modalButtons}>
                    <Button title="Cancel" onPress={() => setNoteModalVisible(false)} color="#FF3B30" />
                    <View style={{ width: 10 }} />
                    <Button title="Save" onPress={handleUpdateNote} />
                </View>
            </View>
        </View>
      </Modal>
    </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#246A73',
  },
  header: {
    paddingHorizontal: 15,
    paddingVertical: 15,
    backgroundColor: '#246A73',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#fff',
  },
  backButton: {
    padding: 5,
    alignSelf: 'flex-start',
  },
  container: {
    flexGrow: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'flex-start',
    padding: 20,
  },
  previewContainer: {
    width: '100%',
    aspectRatio: 3/4,
    backgroundColor: '#f0f0f0',
    borderRadius: 10,
    overflow: 'hidden',
    marginBottom: 20,
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#ddd',
  },
  preview: {
    width: '100%',
    height: '100%',
    resizeMode: 'contain',
  },
  thumbnailList: {
    maxHeight: 80,
    marginBottom: 20,
    width: '100%',
  },
  thumbnailContent: {
    paddingHorizontal: 5,
  },
  thumbnailItem: {
    width: 60,
    height: 60,
    marginRight: 10,
    borderRadius: 8,
    borderWidth: 2,
    borderColor: 'transparent',
    overflow: 'hidden',
  },
  thumbnailSelected: {
    borderColor: '#007AFF',
  },
  thumbnailImage: {
    width: '100%',
    height: '100%',
  },
  placeholder: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  placeholderText: {
    color: '#888',
  },
  controls: {
    width: '100%',
  },
  formContainer: {
    width: '100%',
    marginBottom: 20,
  },
  imageActions: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 10,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginTop: 15,
    marginBottom: 5,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 8,
    padding: 10,
    height: 100,
    textAlignVertical: 'top',
  },
  saveButton: {
      marginTop: 10,
  },
  tableContainer: {
    width: '100%',
    marginTop: 10,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    overflow: 'hidden',
  },
  tableHeader: {
    flexDirection: 'row',
    backgroundColor: '#f0f2f5',
    padding: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#ddd',
  },
  tableHeaderText: { fontWeight: 'bold', color: '#333' },
  tableRow: { flexDirection: 'row', padding: 10, borderBottomWidth: 1, borderBottomColor: '#eee', backgroundColor: '#fff' },
  colType: { width: 100, fontWeight: '600', color: '#246A73' },
  colNote: { flex: 1, color: '#333' },
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'center', padding: 20 },
  modalContent: { backgroundColor: '#fff', padding: 20, borderRadius: 10 },
  modalTitle: { fontSize: 18, fontWeight: 'bold', marginBottom: 15 },
  modalInput: { borderWidth: 1, borderColor: '#ddd', padding: 10, borderRadius: 5, marginBottom: 15 },
  modalButtons: { flexDirection: 'row', justifyContent: 'flex-end' },
});
