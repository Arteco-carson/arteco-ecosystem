// src/components/Input.js
import React from 'react';
import { TextInput, StyleSheet, View, Text } from 'react-native';

export const Input = ({ label, ...props }) => (
  <View style={styles.container}>
    {label && <Text style={styles.label}>{label}</Text>}
    <TextInput 
      style={styles.input} 
      placeholderTextColor="#94a3b8"
      {...props} 
    />
  </View>
);

const styles = StyleSheet.create({
  container: { marginBottom: 15 },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#64748b',
    marginBottom: 8,
    marginLeft: 4,
  },
  input: {
    backgroundColor: '#fff',
    padding: 15,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#e2e8f0',
    fontSize: 16,
    color: '#1e293b'
  }
});