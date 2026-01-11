import React, { useState, useRef } from 'react';
import { View, Image, StyleSheet, TouchableOpacity, Text, Modal, TextInput, PanResponder, SafeAreaView, Alert } from 'react-native';
import { Square, Circle, ArrowUpRight, Save, X, Trash2, Type, Move, RotateCw } from 'lucide-react-native';

const DraggableAnnotation = ({ annotation, updateAnnotation, deleteAnnotation, onEdit }) => {
  const initialPos = useRef({ x: 0, y: 0 });
  const panResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onPanResponderGrant: () => {
        initialPos.current = { x: annotation.x, y: annotation.y };
      },
      onPanResponderMove: (evt, gestureState) => {
        updateAnnotation(annotation.id, {
          x: initialPos.current.x + gestureState.dx,
          y: initialPos.current.y + gestureState.dy
        });
      },
      onPanResponderRelease: (evt, gestureState) => {
         updateAnnotation(annotation.id, {
          x: initialPos.current.x + gestureState.dx,
          y: initialPos.current.y + gestureState.dy
        });
      }
    })
  ).current;

  // Simple resize logic for bottom-right corner
  const initialSize = useRef({ width: 0, height: 0 });
  const resizeResponder = useRef(
      PanResponder.create({
        onStartShouldSetPanResponder: () => true,
        onPanResponderGrant: () => {
          initialSize.current = { width: annotation.width, height: annotation.height };
        },
        onPanResponderMove: (evt, gestureState) => {
          updateAnnotation(annotation.id, {
            width: Math.max(30, initialSize.current.width + gestureState.dx),
            height: annotation.type === 'Circle' 
              ? Math.max(30, initialSize.current.width + gestureState.dx) // Keep circle aspect
              : Math.max(30, initialSize.current.height + gestureState.dy)
          });
        },
      })
    ).current;

  // Rotation logic for Arrow
  const initialRotation = useRef(0);
  const rotateResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onPanResponderGrant: () => {
        initialRotation.current = annotation.rotation || 0;
      },
      onPanResponderMove: (evt, gestureState) => {
        updateAnnotation(annotation.id, {
          rotation: (initialRotation.current + gestureState.dx) % 360
        });
      },
    })
  ).current;

  // Text Drag Logic
  const initialTextOffset = useRef({ x: 0, y: 0 });
  const textResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onPanResponderGrant: () => {
        initialTextOffset.current = annotation.textOffset || { x: 0, y: 50 };
      },
      onPanResponderMove: (evt, gestureState) => {
        // Adjust drag delta for parent rotation so dragging feels natural (screen aligned)
        const rad = (annotation.rotation || 0) * (Math.PI / 180);
        const cos = Math.cos(rad);
        const sin = Math.sin(rad);
        const dx = gestureState.dx * cos + gestureState.dy * sin;
        const dy = gestureState.dy * cos - gestureState.dx * sin;

        updateAnnotation(annotation.id, {
          textOffset: { x: initialTextOffset.current.x + dx, y: initialTextOffset.current.y + dy }
        });
      },
    })
  ).current;

  const rotation = annotation.rotation || 0;
  const normalizedRotation = ((rotation % 360) + 360) % 360;
  const isUpsideDown = normalizedRotation > 90 && normalizedRotation < 270;

  return (
    <View
      style={[
        styles.annotationItem,
        {
          left: annotation.x,
          top: annotation.y,
          width: annotation.width,
          height: annotation.type === 'Arrow' ? 80 : annotation.height, // Fixed height for arrow container
          transform: [{ rotate: `${rotation}deg` }]
        }
      ]}
    >
      {/* Drag Handle (Center) */}
      <View {...panResponder.panHandlers} style={styles.dragArea}>
          {annotation.type === 'Rectangle' && (
              <View style={[styles.shapeRect, { width: '100%', height: '100%' }]} />
          )}
          {annotation.type === 'Circle' && (
              <View style={[styles.shapeCircle, { width: '100%', height: '100%', borderRadius: 999 }]} />
          )}
          {annotation.type === 'Arrow' && (
              <ArrowUpRight size={60} color="#FF3B30" strokeWidth={3} />
          )}
      </View>

      {/* Resize Handle (Bottom Right) - Not for Arrow */}
      {annotation.type !== 'Arrow' && (
          <View {...resizeResponder.panHandlers} style={styles.resizeHandle} />
      )}

      {/* Rotation Handle (Bottom Right) - Only for Arrow */}
      {annotation.type === 'Arrow' && (
          <View {...rotateResponder.panHandlers} style={styles.rotateHandle}>
              <RotateCw size={14} color="#000" />
          </View>
      )}

      {/* Actions */}
      <View style={styles.itemActions}>
          <TouchableOpacity onPress={() => deleteAnnotation(annotation.id)} style={styles.actionBtn}>
              <Trash2 size={16} color="#fff" />
          </TouchableOpacity>
          <TouchableOpacity onPress={() => onEdit(annotation.id, annotation.text)} style={styles.actionBtn}>
              <Type size={16} color="#fff" />
          </TouchableOpacity>
      </View>
      
      {/* Text Label Preview */}
      {annotation.text ? (
          <View 
            {...textResponder.panHandlers}
            style={[
              styles.textPreview,
              { 
                transform: [
                  { translateX: annotation.textOffset?.x || 0 },
                  { translateY: annotation.textOffset?.y || 50 },
                  { rotate: isUpsideDown ? '180deg' : '0deg' }
                ] 
              }
          ]}>
              <Text style={styles.textPreviewContent} numberOfLines={1}>{annotation.text}</Text>
          </View>
      ) : null}
    </View>
  );
};

export const ConditionPointerAnnotator = ({ imageUrl, initialPaths = [], onSave, onCancel }) => {
  const [annotations, setAnnotations] = useState(initialPaths || []);
  const [currentTool, setCurrentTool] = useState(null); // 'Rectangle', 'Circle', 'Arrow'
  const [textModalVisible, setTextModalVisible] = useState(false);
  const [currentText, setCurrentText] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [containerLayout, setContainerLayout] = useState({ width: 0, height: 0 });

  const handleAddAnnotation = (type) => {
    const newId = Date.now().toString();
    const newAnnotation = {
      id: newId,
      type,
      x: containerLayout.width / 2 - 40, // Center
      y: containerLayout.height / 2 - 40,
      width: 80,
      height: 80,
      text: '',
      rotation: 0,
      textOffset: { x: 0, y: 50 }, // Default position below center
    };
    setAnnotations([...annotations, newAnnotation]);
    setEditingId(newId);
    setCurrentText('');
    setTextModalVisible(true);
  };

  const updateAnnotation = (id, updates) => {
    setAnnotations(prev => prev.map(a => a.id === id ? { ...a, ...updates } : a));
  };

  const saveText = () => {
    if (editingId) {
      updateAnnotation(editingId, { text: currentText });
    }
    setTextModalVisible(false);
    setEditingId(null);
  };

  const deleteAnnotation = (id) => {
    setAnnotations(prev => prev.filter(a => a.id !== id));
  };

  const handleClearAll = () => {
    Alert.alert(
      'Clear All',
      'Are you sure you want to remove all annotations?',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Clear', style: 'destructive', onPress: () => setAnnotations([]) },
      ]
    );
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={onCancel}><X color="#fff" size={24} /></TouchableOpacity>
        <Text style={styles.headerTitle}>Annotate Condition</Text>
        <TouchableOpacity onPress={() => onSave(annotations, containerLayout.width, containerLayout.height)}><Save color="#fff" size={24} /></TouchableOpacity>
      </View>

      <View 
        style={styles.canvasContainer} 
        onLayout={(e) => setContainerLayout(e.nativeEvent.layout)}
      >
        <Image source={{ uri: imageUrl }} style={styles.image} resizeMode="contain" />
        
        {annotations.map(ann => (
            <DraggableAnnotation 
              key={ann.id} 
              annotation={ann} 
              updateAnnotation={updateAnnotation}
              deleteAnnotation={deleteAnnotation}
              onEdit={(id, text) => {
                setEditingId(id);
                setCurrentText(text);
                setTextModalVisible(true);
              }}
            />
        ))}
      </View>

      <View style={styles.toolbar}>
        <TouchableOpacity style={styles.toolButton} onPress={() => handleAddAnnotation('Rectangle')}>
            <Square color="#fff" size={24} />
            <Text style={styles.toolText}>Rectangle</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.toolButton} onPress={() => handleAddAnnotation('Circle')}>
            <Circle color="#fff" size={24} />
            <Text style={styles.toolText}>Circle</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.toolButton} onPress={() => handleAddAnnotation('Arrow')}>
            <ArrowUpRight color="#fff" size={24} />
            <Text style={styles.toolText}>Arrow</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.toolButton} onPress={handleClearAll}>
            <Trash2 color="#FF3B30" size={24} />
            <Text style={[styles.toolText, { color: '#FF3B30' }]}>Clear All</Text>
        </TouchableOpacity>
      </View>

      <Modal visible={textModalVisible} transparent animationType="fade">
        <View style={styles.modalOverlay}>
            <View style={styles.modalContent}>
                <Text style={styles.modalTitle}>Condition Note</Text>
                <TextInput
                    style={styles.input}
                    value={currentText}
                    onChangeText={setCurrentText}
                    placeholder="Describe the condition..."
                    autoFocus
                />
                <TouchableOpacity style={styles.saveBtn} onPress={saveText}>
                    <Text style={styles.saveBtnText}>Save Note</Text>
                </TouchableOpacity>
            </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000' },
  header: { flexDirection: 'row', justifyContent: 'space-between', padding: 15, alignItems: 'center' },
  headerTitle: { color: '#fff', fontSize: 18, fontWeight: 'bold' },
  canvasContainer: { flex: 1, position: 'relative', overflow: 'hidden', backgroundColor: '#333' },
  image: { width: '100%', height: '100%' },
  toolbar: { flexDirection: 'row', justifyContent: 'space-around', padding: 20, backgroundColor: '#222' },
  toolButton: { alignItems: 'center' },
  toolText: { color: '#fff', marginTop: 5, fontSize: 12 },
  
  annotationItem: { position: 'absolute' },
  dragArea: { flex: 1 },
  shapeRect: { borderWidth: 3, borderColor: '#FF3B30', backgroundColor: 'rgba(255, 59, 48, 0.2)' },
  shapeCircle: { borderWidth: 3, borderColor: '#FF3B30', backgroundColor: 'rgba(255, 59, 48, 0.2)' },
  
  resizeHandle: {
    position: 'absolute', bottom: -10, right: -10, width: 20, height: 20,
    backgroundColor: '#fff', borderRadius: 10, borderWidth: 1, borderColor: '#000'
  },
  rotateHandle: {
    position: 'absolute', bottom: -10, right: -10, width: 24, height: 24,
    backgroundColor: '#FFD700', borderRadius: 12, borderWidth: 1, borderColor: '#000',
    justifyContent: 'center', alignItems: 'center'
  },
  itemActions: {
    position: 'absolute', top: -30, right: 0, flexDirection: 'row',
    backgroundColor: 'rgba(0,0,0,0.6)', borderRadius: 5, padding: 2
  },
  actionBtn: { padding: 5 },
  textPreview: {
    position: 'absolute', top: '50%', left: '50%',
    backgroundColor: 'rgba(0,0,0,0.7)', padding: 4, borderRadius: 4,
    minWidth: 60, alignItems: 'center', justifyContent: 'center',
    marginLeft: -30, marginTop: -10 // Rough centering adjustment
  },
  textPreviewContent: { color: '#fff', fontSize: 10, textAlign: 'center' },

  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'center', padding: 20 },
  modalContent: { backgroundColor: '#fff', padding: 20, borderRadius: 10 },
  modalTitle: { fontSize: 18, fontWeight: 'bold', marginBottom: 15 },
  input: { borderWidth: 1, borderColor: '#ddd', padding: 10, borderRadius: 5, marginBottom: 15 },
  saveBtn: { backgroundColor: '#007AFF', padding: 12, borderRadius: 5, alignItems: 'center' },
  saveBtnText: { color: '#fff', fontWeight: 'bold' }
});