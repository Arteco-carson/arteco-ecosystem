import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Switch, Alert, ActivityIndicator, SafeAreaView } from 'react-native';
import axios from 'axios';
import { BASE_URL } from '../config/env';
import { register as registerService } from '../services/authservice';
import { User, Mail, Lock, Tag } from 'lucide-react-native';

const RegisterScreen = ({ navigation }) => {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    username: '',
    email: '',
    password: '',
    roleId: 1,
    marketingConsent: false
  });
  const [roles, setRoles] = useState([
    { roleId: 1, roleName: 'Guest' },
    { roleId: 2, roleName: 'Manager' },
    { roleId: 3, roleName: 'Admin' }
  ]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchRoles = async () => {
      try {
        const response = await axios.get(`${BASE_URL}/userroles`);
        if (response.data && response.data.length > 0) {
          setRoles(response.data);
        }
      } catch (error) {
        console.log('Failed to fetch roles, using defaults');
      }
    };
    fetchRoles();
  }, []);

  const handleChange = (name, value) => {
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleRegister = async () => {
    if (!formData.firstName || !formData.lastName || !formData.username || !formData.email || !formData.password) {
      Alert.alert('Validation Error', 'Please fill in all required fields.');
      return;
    }

    setLoading(true);
    try {
      const payload = {
        firstName: formData.firstName,
        lastName: formData.lastName,
        username: formData.username,
        email: formData.email,
        password: formData.password,
        externalUserId: formData.email,
        roleId: formData.roleId,
        userTypeId: 2,
        marketingConsent: formData.marketingConsent
      };
      
      await registerService(payload);
      Alert.alert('Success', 'Profile created successfully. Please log in.', [
        { text: 'OK', onPress: () => navigation.navigate('Login') }
      ]);
    } catch (error) {
      console.error(error);
      Alert.alert('Registration Failed', 'Could not create account. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Text style={styles.title}>Create Profile</Text>
          <Text style={styles.subtitle}>Arteco Operations Enrolment</Text>
        </View>

        <View style={styles.card}>
          <View style={styles.row}>
            <View style={[styles.inputContainer, { flex: 1, marginRight: 5 }]}>
              <User color="#94a3b8" size={18} style={styles.icon} />
              <TextInput
                style={styles.input}
                placeholder="First Name"
                value={formData.firstName}
                onChangeText={(text) => handleChange('firstName', text)}
              />
            </View>
            <View style={[styles.inputContainer, { flex: 1, marginLeft: 5 }]}>
              <User color="#94a3b8" size={18} style={styles.icon} />
              <TextInput
                style={styles.input}
                placeholder="Last Name"
                value={formData.lastName}
                onChangeText={(text) => handleChange('lastName', text)}
              />
            </View>
          </View>

          <View style={styles.inputContainer}>
            <Tag color="#94a3b8" size={18} style={styles.icon} />
            <TextInput
              style={styles.input}
              placeholder="Username"
              value={formData.username}
              onChangeText={(text) => handleChange('username', text)}
              autoCapitalize="none"
            />
          </View>

          <View style={styles.inputContainer}>
            <Mail color="#94a3b8" size={18} style={styles.icon} />
            <TextInput
              style={styles.input}
              placeholder="Work Email"
              value={formData.email}
              onChangeText={(text) => handleChange('email', text)}
              keyboardType="email-address"
              autoCapitalize="none"
            />
          </View>

          <View style={styles.inputContainer}>
            <Lock color="#94a3b8" size={18} style={styles.icon} />
            <TextInput
              style={styles.input}
              placeholder="Password"
              value={formData.password}
              onChangeText={(text) => handleChange('password', text)}
              secureTextEntry
            />
          </View>

          {/* Simple Role Selection */}
          <Text style={styles.label}>System Role</Text>
          <View style={styles.roleContainer}>
            {roles.map(role => (
              <TouchableOpacity
                key={role.roleId}
                style={[styles.roleButton, formData.roleId === role.roleId && styles.roleButtonActive]}
                onPress={() => handleChange('roleId', role.roleId)}
              >
                <Text style={[styles.roleText, formData.roleId === role.roleId && styles.roleTextActive]}>{role.roleName}</Text>
              </TouchableOpacity>
            ))}
          </View>

          <View style={styles.switchContainer}>
            <Switch
              value={formData.marketingConsent}
              onValueChange={(val) => handleChange('marketingConsent', val)}
              trackColor={{ false: "#767577", true: "#246A73" }}
            />
            <Text style={styles.switchLabel}>I consent to data processing for system notifications.</Text>
          </View>

          <TouchableOpacity 
            style={styles.button} 
            onPress={handleRegister}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="white" />
            ) : (
              <Text style={styles.buttonText}>Register Account</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity onPress={() => navigation.goBack()} style={styles.linkButton}>
            <Text style={styles.linkText}>Already have a profile? Login</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  scrollContent: { padding: 20 },
  header: { alignItems: 'center', marginBottom: 30, marginTop: 20 },
  title: { fontSize: 24, fontWeight: 'bold', color: '#1e293b' },
  subtitle: { fontSize: 14, color: '#64748b', marginTop: 5 },
  card: { backgroundColor: 'white', padding: 20, borderRadius: 12, shadowColor: '#000', shadowOpacity: 0.05, shadowRadius: 10, elevation: 3 },
  row: { flexDirection: 'row', marginBottom: 15 },
  inputContainer: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, marginBottom: 15, paddingHorizontal: 10, height: 50 },
  icon: { marginRight: 10 },
  input: { flex: 1, color: '#1e293b' },
  label: { fontSize: 14, fontWeight: 'bold', color: '#475569', marginBottom: 8 },
  roleContainer: { flexDirection: 'row', marginBottom: 20, backgroundColor: '#f8fafc', padding: 4, borderRadius: 8 },
  roleButton: { flex: 1, paddingVertical: 8, alignItems: 'center', borderRadius: 6 },
  roleButtonActive: { backgroundColor: 'white', shadowColor: '#000', shadowOpacity: 0.1, shadowRadius: 2, elevation: 2 },
  roleText: { color: '#64748b', fontSize: 13 },
  roleTextActive: { color: '#246A73', fontWeight: 'bold' },
  switchContainer: { flexDirection: 'row', alignItems: 'center', marginBottom: 25 },
  switchLabel: { flex: 1, marginLeft: 10, fontSize: 12, color: '#64748b' },
  button: { backgroundColor: '#246A73', height: 50, borderRadius: 8, justifyContent: 'center', alignItems: 'center' },
  buttonText: { color: 'white', fontWeight: 'bold', fontSize: 16 },
  linkButton: { marginTop: 20, alignItems: 'center' },
  linkText: { color: '#64748b', fontSize: 14 }
});

export default RegisterScreen;